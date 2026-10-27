// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Scheduling of runner processes' threads, and the broker's, on the CPUs.
//!
//! One run queue ([`Scheduler`]) holds every process. Each CPU takes steps
//! (the boot CPU in [`Scheduler::run_until`], between its services' calls;
//! the others in [`Scheduler::run`]): it looks at the devices, polls the
//! threads and the broker's threads, and runs the best runnable thread
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
//! The broker's threads (see `litebox_broker_vm_kernel`) are preemptible
//! kernel threads, which hold no claim. A thread's broker call waits for the
//! association thread that works for it, which uses its CPU time (see
//! `Account`); other broker work uses its own.
//!
//! What may make work for another CPU wakes it (see `claim` and
//! [`litebox_platform_vm_kernel::cpu`]): adding a process, releasing one with
//! work left, or one it found claimed; a notification to a waiting process,
//! which has every CPU look again within `NOTIFIED`; queuing or waking a
//! broker thread (see [`cpu::wake_idle_or_resched`]); and a device interrupt,
//! which wakes the idle CPUs to poll the devices.
//!
//! Nothing runs once every process waits for a request, is dead, or is a
//! process clone not adopted yet, none is claimed, no thread runs, and no
//! association thread exists. Waits that nothing could end
//! ([`Status::Stalled`]) are abandoned by the boot CPU, once no other CPU runs
//! anything.
//!
//! Known limitations:
//! - A run, or a broker thread's run, is charged at most one slice of CPU
//!   time (see `charged`), because the clock cannot tell long kernel work from
//!   time the host did not run the vCPU. A thread whose runs regularly exceed
//!   a slice therefore gets more than its share of the CPU.
//! - A notification to any waiting process shortens every busy CPU's slice.
//! - A process running on another CPU, with no thread waiting for
//!   notifications, sees one only at its next kernel entry, at the latest as
//!   its slice ends.
//! - A thread whose kernel entry finds its process's claim held past a brief
//!   spin (e.g., by a step that polls many of its threads, or by
//!   its other threads' entries, long ones or many in a row) is parked (see
//!   [`Scheduler::parks`]), until a step claims the process again. Its CPU
//!   steps again at once, and wakes the idle CPUs; but if the claim is still
//!   held, and no CPU is idle once it is released, the thread waits for a busy
//!   CPU's next step, up to a slice later.
//! - A broker thread preempted past its grace while holding a lock delays the
//!   broker threads that need it until it runs again.

use crate::claim::{Claim, Owned};
use crate::thread::{FutexState, Thread};
use crate::{BrokerCall, Ended, Inner, ProcessTimer, Running, Suspended, Unclaimed};
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;
#[cfg(debug_assertions)]
use core::sync::atomic::AtomicBool;
#[cfg(debug_assertions)]
use core::sync::atomic::AtomicU8;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;
use litebox_broker_vm_kernel::{
    Broker, BrokerHandle, EnterError, Events, Started, ThreadWork, WaitState,
};
use litebox_common_vm_abi::Status;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId, MAX_CPUS, NOTIFIED};
use litebox_platform_vm_kernel::kthread::{self, Check, Kthread, Point, Ran, Stack};
use litebox_platform_vm_kernel::{Instant, VmKernel};
use spin::mutex::SpinMutex;

const QUANTUM_NANOS: u64 = 10_000_000;
/// The length of a slice.
pub const QUANTUM: Duration = Duration::from_nanos(QUANTUM_NANOS);
/// How long a kernel thread's run goes on past its slice end without reaching
/// a safe point: as long as a thread runs on once notified.
pub const GRACE: Duration = NOTIFIED;

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
    /// spawning, halting, or dropping a process.
    queue: SpinMutex<RunQueue>,
    /// Per CPU, by index; shared with the processes, which count the attempts
    /// to take their claims there (see `Owned`).
    counts: Arc<[CpuCounts; MAX_CPUS]>,
    events: &'static dyn Events,
    timer: &'static dyn ProcessTimer,
    platform: &'static VmKernel,
    /// The next [`Owned::seq`].
    next_seq: AtomicU64,
    broker: spin::Once<BrokerHandle>,
    #[cfg(debug_assertions)]
    hooks: SchedulerHooks,
}

/// Debug builds: tests' hooks into the scheduler's work with the broker.
#[cfg(debug_assertions)]
#[derive(Default)]
pub struct SchedulerHooks {
    /// While set, steps start no launched process.
    pub hold_starts: AtomicBool,
    /// A step held a start.
    pub held_start: AtomicBool,
    /// If nonzero, broker threads' slices last this many nanoseconds at most,
    /// with no grace.
    pub broker_slice: AtomicU64,
    /// The [`RetakeHold`] to hold, as a number; 0 for none.
    retake_case: AtomicU8,
    /// A handoff was held as [`Self::hold_retake`] asked.
    pub retaken: AtomicBool,
    /// The next broker thread to finish bound has its inbox posted to then.
    pub post_as_finished: AtomicBool,
    reaped: SpinMutex<Option<Vec<Arc<Owned>>>>,
    /// While set, the boot CPU looks again at least every millisecond.
    pub poll: AtomicBool,
}

/// Debug builds: a handoff to hold until another CPU did what the case says.
#[cfg(debug_assertions)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum RetakeHold {
    /// A handshake's, finished, before its retake: until another CPU runs the
    /// caller. `Over`.
    Handshake = 1,
    /// A `Futex` call's, finished, before its retake: until another CPU's
    /// turn looked at the caller. Resumed.
    Futex,
    /// A `Futex` call's, queued, before its `try_claim`: until another CPU
    /// runs the caller. `Over`.
    PreemptedFutex,
    /// As [`Self::PreemptedFutex`], until that run ended. `Over`.
    PreemptedFutexRan,
}

/// Debug builds: [`Thread::retake_hold`]'s states.
#[cfg(debug_assertions)]
const HOLD_LOOK: u8 = 1;
#[cfg(debug_assertions)]
const HOLD_RUN: u8 = 2;
#[cfg(debug_assertions)]
const HOLD_RAN: u8 = 3;
#[cfg(debug_assertions)]
const HOLD_DONE: u8 = 4;

#[cfg(debug_assertions)]
fn latch_retake_hold(thread: &Thread, event: u8) {
    // A load first, so that turns and runs do not write the line.
    if thread.retake_hold.load(Ordering::Relaxed) == event {
        let _ = thread.retake_hold.compare_exchange(
            event,
            HOLD_DONE,
            Ordering::SeqCst,
            Ordering::SeqCst,
        );
    }
}

#[cfg(debug_assertions)]
impl SchedulerHooks {
    /// Holds the next handoff that matches `case`, if any.
    pub fn hold_retake(&self, case: Option<RetakeHold>) {
        self.retake_case
            .store(case.map_or(0, |case| case as u8), Ordering::SeqCst);
    }

    fn retake_case(&self) -> Option<RetakeHold> {
        [
            RetakeHold::Handshake,
            RetakeHold::Futex,
            RetakeHold::PreemptedFutex,
            RetakeHold::PreemptedFutexRan,
        ]
        .into_iter()
        .find(|&case| case as u8 == self.retake_case.load(Ordering::Relaxed))
    }

    /// Keeps the processes reaped from then on, for the shutdown to drop.
    pub fn keep_reaped(&self) {
        self.reaped.lock().get_or_insert_default();
    }

    fn broker_slice_end(&self, now: Instant) -> Option<Instant> {
        match self.broker_slice.load(Ordering::Relaxed) {
            0 => None,
            slice => now.checked_add(Duration::from_nanos(slice)),
        }
    }
}

/// A CPU's counts, which only it changes: on a cache line of its own, so that
/// CPUs counting at once (e.g., on every kernel entry) do not contend.
#[derive(Default)]
#[repr(align(64))]
pub(crate) struct CpuCounts {
    /// Its attempts to take a claim of the scheduler's processes, and its
    /// broker threads' runs, each counted just before, taken or not (see
    /// [`Shared::claim_attempts`]).
    pub(crate) claims: AtomicU64,
    /// The slices it ran.
    slices: AtomicU64,
    /// The threads it parked (see [`Scheduler::parks`]).
    parks: AtomicU64,
}

#[derive(Default)]
struct RunQueue {
    /// The live processes, and the dead ones with broker work in flight.
    processes: Vec<Arc<Owned>>,
    brokers: Vec<BrokerThread>,
    /// The broker threads that CPUs run, by role.
    running_associations: usize,
    source_running: bool,
    /// Debug builds: the CPUs that run association threads, by bit.
    #[cfg(debug_assertions)]
    running_association_cpus: u64,
    /// Where the round-robin for ties starts: after this thread, as its
    /// process's [`Owned::seq`] and its ID.
    last: (u64, u64),
    /// The least CPU time of the threads that could run, as of the last
    /// slice (of any CPU).
    floor: u64,
    next_broker: u64,
}

impl RunQueue {
    fn start_run(&mut self, role: Role) {
        match role {
            Role::Association => {
                self.running_associations += 1;
                #[cfg(debug_assertions)]
                {
                    self.running_association_cpus |= bit(cpu::current());
                }
            }
            Role::Source => self.source_running = true,
        }
    }

    fn end_run(&mut self, role: Role) {
        match role {
            Role::Association => {
                self.running_associations -= 1;
                #[cfg(debug_assertions)]
                {
                    self.running_association_cpus &= !bit(cpu::current());
                }
            }
            Role::Source => self.source_running = false,
        }
    }
}

struct BrokerThread {
    /// Its place among broker threads' ties, which go before threads'.
    id: u64,
    role: Role,
    run: BrokerRun,
    account: Account,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Association,
    Source,
}

enum BrokerRun {
    Start(ThreadWork),
    Started(Kthread, Started),
}

/// Whose CPU time a broker thread uses, which orders it.
enum Account {
    /// Its caller's: keyed by the caller's CPU time at the call plus its runs,
    /// floored as a thread's; only its runs fold into the caller's.
    Caller {
        broker_time: Arc<AtomicU64>,
        key: u64,
        ran: u64,
    },
    Own(u64),
}

impl Account {
    fn key(&self) -> u64 {
        match *self {
            Self::Caller { key, .. } | Self::Own(key) => key,
        }
    }

    /// Its key, [`counted`], which it keeps.
    fn counted(&mut self, floor: u64) -> u64 {
        let (Self::Caller { key, .. } | Self::Own(key)) = self;
        *key = counted(*key, floor);
        *key
    }

    fn charge(&mut self, used: u64) {
        match self {
            Self::Caller { key, ran, .. } => {
                *key = key.saturating_add(used);
                *ran = ran.saturating_add(used);
            }
            Self::Own(cpu_time) => *cpu_time = cpu_time.saturating_add(used),
        }
    }

    fn finish(self) {
        if let Self::Caller {
            broker_time, ran, ..
        } = self
        {
            broker_time.fetch_add(ran, Ordering::Relaxed);
        }
    }
}

impl Scheduler {
    /// One that halts with the runner's `events` (see [`Events::wait`]) when
    /// nothing can run.
    pub fn new(
        events: &'static dyn Events,
        timer: &'static dyn ProcessTimer,
        platform: &'static VmKernel,
    ) -> Self {
        Self(Arc::new(Shared {
            queue: SpinMutex::new(RunQueue::default()),
            counts: Arc::new(core::array::from_fn(|_| CpuCounts::default())),
            events,
            timer,
            platform,
            next_seq: AtomicU64::new(1),
            broker: spin::Once::new(),
            #[cfg(debug_assertions)]
            hooks: SchedulerHooks::default(),
        }))
    }

    /// Debug builds: tests' hooks.
    #[cfg(debug_assertions)]
    pub fn hooks(&self) -> &SchedulerHooks {
        &self.0.hooks
    }

    /// Runs the processes until `done`, checked between steps, or until
    /// nothing runs (see the [module](self) docs), without checking `done`
    /// after that last step. On the boot CPU, which a process that stops
    /// wakes, as does the end of its broker work, or of the source thread: so
    /// `done` must change only so (e.g., [`crate::Process::is_stopped`]).
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
    /// found its process's claim held past a brief spin, or, in debug builds,
    /// was made to give up (see `ProcessConfig::give_up_once`), for
    /// diagnostics (see the [module](self) docs).
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

    /// Forgets the dead processes with no broker work in flight, which
    /// releases their address spaces unless a [`crate::Process`] holds them.
    /// Another CPU may release some a moment later (e.g., ones its step
    /// holds, or that it forgot first).
    pub fn reap(&self) {
        self.0.reap();
    }

    /// Starts running `broker`'s threads, before any process is associated.
    ///
    /// # Panics
    ///
    /// On a second call, or if no stack is left.
    pub fn start_broker(&self, broker: &Broker) {
        let mut started = false;
        self.0.broker.call_once(|| {
            started = true;
            broker.handle()
        });
        assert!(started, "the broker's threads are already started");
        let stack = Stack::allocate().expect("a stack for the broker's source thread");
        let mut queue = self.0.queue.lock();
        let id = queue.next_broker;
        queue.next_broker += 1;
        let account = Account::Own(queue.floor);
        queue.brokers.push(BrokerThread {
            id,
            role: Role::Source,
            run: BrokerRun::Start(broker.source(stack)),
            account,
        });
    }

    /// Ends the broker's threads, then drops `broker`, on the boot CPU, once
    /// every process is dead.
    ///
    /// # Panics
    ///
    /// If a process is alive, or broker state is left.
    pub fn shut_down_broker(&self, broker: Broker) {
        let shared = &self.0;
        self.run_until(|| shared.broker_drained());
        assert!(
            shared
                .queue
                .lock()
                .processes
                .iter()
                .all(|process| process.is_dead()),
            "every process is dead as the broker shuts down"
        );
        broker.stop_source();
        let ended = || {
            let queue = shared.queue.lock();
            queue.brokers.is_empty() && !queue.source_running
        };
        // Another CPU that runs the source thread wakes this one as it ends.
        loop {
            self.run_until(ended);
            if ended() {
                break;
            }
            cpu::halt();
        }
        assert!(
            shared.broker_drained() && ended(),
            "the broker's threads ended"
        );
        assert_eq!(kthread::live(), 0, "no broker thread is left");
        assert_eq!(kthread::stacks(), 0, "every broker stack is freed");
        assert_eq!(broker.sides(), 0, "every association ended");
        assert!(broker.is_unshared(), "no broker work is left");
        drop(broker);
        #[cfg(debug_assertions)]
        if let Some(kept) = self.0.hooks.reaped.lock().take() {
            assert!(
                !kept.is_empty(),
                "a reaped process was kept past the shutdown"
            );
            drop(kept);
        }
    }
}

/// Lazy, as a thread's run in the kernel is: see `check_run`.
impl kthread::Preemption for Scheduler {
    fn check(&self, point: Point, slice_end: Option<Instant>) -> Check {
        if point == Point::Interrupt {
            self.0.poll_devices();
        }
        let resched = cpu::take_resched();
        let marks = Marks {
            resched,
            notified: !resched && cpu::take_notified(),
            alone: cpu::online_count() == 1,
        };
        let now = self.0.platform.now();
        let (check, arm) = check_run(point, now, slice_end, self.0.grace(), marks);
        if let Some(arm) = arm {
            self.0.timer.arm_if_earlier(arm);
        }
        check
    }

    fn end_slice(&self, slice_end: Option<Instant>) -> Instant {
        let end = end_by(slice_end, self.0.platform.now(), Duration::ZERO);
        self.0.timer.arm_if_earlier(past_grace(end, self.0.grace()));
        end
    }
}

/// The marks a check took from its CPU, and whether it is alone online.
#[derive(Clone, Copy, Debug, Default)]
struct Marks {
    resched: bool,
    notified: bool,
    alone: bool,
}

/// The policy for a kernel thread's run, checked at `point` at `now`, its
/// slice ending at `slice_end`. The `marks` shorten the end: to now to
/// reschedule, or notified alone online; else within [`NOTIFIED`] if notified.
/// The run ends at a safe point once past its end, where it holds nothing
/// others wait for; at an interrupt only `grace` past it, as it may hold a
/// spin lock there. Otherwise the timer is to be armed for the grace past an
/// end the marks shortened, which stays the run's, or at an interrupt.
fn check_run(
    point: Point,
    now: Instant,
    slice_end: Option<Instant>,
    grace: Duration,
    marks: Marks,
) -> (Check, Option<Instant>) {
    let Marks {
        resched,
        notified,
        alone,
    } = marks;
    let end = if resched || (notified && alone) {
        Some(end_by(slice_end, now, Duration::ZERO))
    } else if notified {
        Some(end_by(slice_end, now, NOTIFIED))
    } else {
        slice_end
    };
    let limit = match point {
        Point::SafePoint => end,
        Point::Interrupt => end.map(|end| past_grace(end, grace)),
    };
    if limit.is_some_and(|limit| now >= limit) {
        return (Check::Preempt, None);
    }
    let arm = end
        .filter(|&end| point == Point::Interrupt || Some(end) != slice_end)
        .map(|end| past_grace(end, grace));
    (Check::Continue(end), arm)
}

fn past_grace(end: Instant, grace: Duration) -> Instant {
    end.checked_add(grace)
        .unwrap_or(Instant::from_nanos(u64::MAX))
}

/// `slice_end`, none being never, but `duration` from `now` at the latest.
fn end_by(slice_end: Option<Instant>, now: Instant, duration: Duration) -> Instant {
    let end = now
        .checked_add(duration)
        .unwrap_or(Instant::from_nanos(u64::MAX));
    slice_end.map_or(end, |slice_end| slice_end.min(end))
}

/// Ordering of runnable threads, least first: by CPU time, then
/// round-robin, from after [`RunQueue::last`] (see [`Found::poll`]); broker
/// threads' first of ties.
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
    /// The least CPU time of the other runnable threads, and broker threads.
    others: Option<u64>,
    /// That of the processes held by other CPUs, as last polled (see
    /// [`Owned::runnable`]).
    held: Option<u64>,
    /// The earliest of the blocked threads' wakes, broker threads' too.
    wake: Option<Instant>,
    blocked: bool,
    /// An association thread exists, or is due to.
    brokers: bool,
    /// The threads blocked with no wake, as they were.
    forever: Vec<(Weak<Owned>, Arc<Thread>, Suspended)>,
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

/// The CPU time to charge for a thread's run, or a broker thread's, that
/// took `elapsed` nanoseconds: at most one slice. The clock also counts time
/// the host did not run the vCPU, which looks the same as real work; without
/// this cap, a thread charged for such a stall would wait until every other
/// thread caught up with it.
pub(crate) fn charged(elapsed: u64) -> u64 {
    elapsed.min(QUANTUM_NANOS)
}

pub(crate) fn charged_since(platform: &VmKernel, start: Instant) -> u64 {
    charged(platform.now().as_nanos().saturating_sub(start.as_nanos()))
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    [a, b].into_iter().flatten().min()
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
    /// Without it, which another CPU held after its broker call's thread ran;
    /// `cpu_time` as for [`Self::Parked`].
    Released { cpu_time: u64 },
}

impl Shared {
    /// Polls the threads, spawning launched processes, then runs one for a
    /// slice, or halts until one may run. False once nothing runs (see
    /// [`Self::is_idle`]). The caller acknowledged this CPU's wakeups first
    /// (see [`cpu::acknowledge`]): one after has it step again.
    fn step(&self) -> bool {
        let cpu = cpu::current();
        let claims = self.claim_attempts();
        let mut claimed = 0;
        self.reap();
        self.poll_devices();
        if let Some(broker) = self.broker.get() {
            for work in broker.take_queued() {
                let floor = self.queue.lock().floor;
                self.push_broker(BrokerRun::Start(work), Account::Own(floor));
            }
        }
        let (processes, last, floor) = {
            let queue = self.queue.lock();
            (queue.processes.clone(), queue.last, queue.floor)
        };
        // Whether a claim taken before `claims` was read may still be held:
        // every other is counted, or was released before, its effects seen by
        // the polls (see `Self::quiet`).
        let held = processes.iter().any(|process| process.is_held());
        let mut found = Found::default();
        // From a different place on each CPU, so that CPUs polling at once
        // claim different processes (the order does not change the choice).
        let first = cpu.index() % processes.len().max(1);
        let order = || processes[first..].iter().chain(&processes[..first]);
        let mut spawned = Vec::new();
        for process in order() {
            if process.is_quiescent() {
                continue;
            }
            let Some(claim) = process.try_claim() else {
                found.skip(process);
                continue;
            };
            claimed += 1;
            finish_parked(&claim);
            if !self.holds_starts(&claim) {
                claim.spawn_launched(&mut spawned);
            }
            found.poll(claim, floor, last);
        }
        if !spawned.is_empty() {
            if let Some(best) = &found.best {
                best.claim.share();
            }
            drop(found);
            for process in spawned {
                self.add(self.own(process));
            }
            return true;
        }
        if let Some(broker) = self.take_broker(&mut found, floor) {
            if let Some(best) = found.best.take() {
                found.other(best.key.0);
                best.claim.share();
            }
            self.run_broker(cpu, broker, &found);
            return true;
        }
        let Some(best) = found.best.take() else {
            // Not across the halt: a process that dies on another CPU
            // meanwhile is freed then, not once this CPU wakes.
            let found = found.detach();
            drop(processes);
            // None if a claim held as it began may have effects it missed.
            let claims = (!held).then_some(claims + claimed);
            return self.idle(cpu, found, claims);
        };
        self.run_best(cpu, best, &found);
        true
    }

    #[cfg(debug_assertions)]
    fn holds_starts(&self, claim: &Claim<'_>) -> bool {
        if !self.hooks.hold_starts.load(Ordering::Relaxed) {
            return false;
        }
        if claim.broker.has_pending_associations() {
            self.hooks.held_start.store(true, Ordering::SeqCst);
        }
        true
    }

    #[cfg(not(debug_assertions))]
    fn holds_starts(&self, _: &Claim<'_>) -> bool {
        false
    }

    /// Looks at the devices: whether one interrupted.
    fn poll_devices(&self) -> bool {
        match self.broker.get() {
            Some(broker) => broker.poll_devices(),
            None => self.events.poll(),
        }
    }

    fn push_broker(&self, run: BrokerRun, account: Account) {
        {
            let mut queue = self.queue.lock();
            let id = queue.next_broker;
            queue.next_broker += 1;
            queue.brokers.push(BrokerThread {
                id,
                role: Role::Association,
                run,
                account,
            });
        }
        cpu::wake_idle(cpu::current());
    }

    /// Takes the best runnable broker thread if it is better than `found`'s
    /// best, else adds the broker threads to `found`.
    fn take_broker(&self, found: &mut Found<'_>, floor: u64) -> Option<BrokerThread> {
        let now = self.platform.now();
        let mut queue = self.queue.lock();
        found.brokers |= queue.running_associations != 0
            || self.broker.get().is_some_and(|broker| !broker.is_idle());
        let mut best: Option<(Key, usize)> = None;
        for (at, broker) in queue.brokers.iter_mut().enumerate() {
            found.brokers |= broker.role == Role::Association;
            let (due, wake) = match &broker.run {
                BrokerRun::Start(_) => (true, None),
                BrokerRun::Started(thread, _) => (thread.is_due(now), thread.deadline()),
            };
            if !due {
                found.wake = earliest(found.wake, wake);
                continue;
            }
            let key = (broker.account.counted(floor), false, 0, broker.id);
            match best {
                Some((best_key, _)) if best_key <= key => found.other(key.0),
                _ => {
                    if let Some((previous, _)) = best.replace((key, at)) {
                        found.other(previous.0);
                    }
                }
            }
        }
        let (key, at) = best?;
        if found.best.as_ref().is_some_and(|best| best.key <= key) {
            found.other(key.0);
            return None;
        }
        let broker = queue.brokers.swap_remove(at);
        queue.start_run(broker.role);
        Some(broker)
    }

    /// Runs `broker` for a slice; then puts it back, unless it finished.
    fn run_broker(&self, cpu: CpuId, mut broker: BrokerThread, found: &Found<'_>) {
        let now = self.platform.now();
        let (thread, started) = match broker.run {
            BrokerRun::Started(thread, started) => (thread, started),
            BrokerRun::Start(work) => work.start(),
        };
        let alone = found.others.is_none() && cpu::online_count() == 1;
        let slice = (!alone).then(|| {
            now.checked_add(QUANTUM)
                .unwrap_or(Instant::from_nanos(u64::MAX))
        });
        let slice_end = earliest(found.wake, slice);
        #[cfg(debug_assertions)]
        let slice_end = earliest(slice_end, self.hooks.broker_slice_end(now));
        if let Some(slice_end) = slice_end {
            self.timer
                .arm_if_earlier(past_grace(slice_end, self.grace()));
        }
        let counts = &self.counts[cpu.index()];
        counts.claims.fetch_add(1, Ordering::SeqCst);
        counts.slices.fetch_add(1, Ordering::Relaxed);
        let (ran, _) = thread.run(slice_end);
        broker.account.charge(charged_since(self.platform, now));
        let cpu_time = broker.account.key();
        match ran {
            Ran::Finished(stack) => match broker.role {
                Role::Association => {
                    // Before the unbind, whose wake of the boot CPU (see
                    // `Inbox::finished`) must not find it running.
                    self.queue.lock().end_run(Role::Association);
                    self.finish(started, stack);
                    broker.account.finish();
                }
                Role::Source => {
                    // After its stack is freed, which the shutdown checks.
                    self.finish(started, stack);
                    self.queue.lock().end_run(Role::Source);
                    broker.account.finish();
                    cpu::wake(CpuId::BOOT);
                }
            },
            Ran::Slept(thread) | Ran::Preempted(thread) => {
                broker.run = BrokerRun::Started(thread, started);
                self.put_back(broker);
            }
        }
        let runnable = [found.others, found.held]
            .into_iter()
            .flatten()
            .fold(cpu_time, u64::min);
        let mut queue = self.queue.lock();
        queue.floor = queue.floor.max(runnable);
    }

    /// Gives `started`'s stack back, which may wake the boot CPU: by then,
    /// this CPU must count no association thread as running (checked in
    /// debug builds).
    fn finish(&self, started: Started, stack: Stack) {
        #[cfg(debug_assertions)]
        if self.hooks.post_as_finished.load(Ordering::Relaxed) && started.post_requests() {
            self.hooks.post_as_finished.store(false, Ordering::SeqCst);
        }
        started.finish(stack);
        #[cfg(debug_assertions)]
        assert!(
            self.queue.lock().running_association_cpus & bit(cpu::current()) == 0,
            "an association thread is counted out before its unbind"
        );
    }

    /// [`GRACE`], unless [`SchedulerHooks::broker_slice`] caps slices.
    fn grace(&self) -> Duration {
        #[cfg(debug_assertions)]
        if self.hooks.broker_slice.load(Ordering::Relaxed) != 0 {
            return Duration::ZERO;
        }
        GRACE
    }

    fn put_back(&self, broker: BrokerThread) {
        let mut queue = self.queue.lock();
        queue.end_run(broker.role);
        queue.brokers.push(broker);
    }

    /// Runs the best thread a step found for a slice.
    ///
    /// If its broker calls end at once, or it cloned its process (see
    /// `crate::fork`), it runs more of its slice, unless a run parks it. If the
    /// process has other runnable threads, the other idle CPUs are woken to
    /// run them meanwhile. The slice ends early once another may run: a blocked
    /// thread's deadline, or soon after a notification. With one CPU, a thread
    /// alone has no slice end; with more, every run has one, as other CPUs may
    /// make more runnable unseen (e.g., processes they held, start, or end the
    /// waits of), or need the boot CPU's services to look between slices at
    /// what they wait for.
    fn run_best(&self, cpu: CpuId, best: Best<'_>, found: &Found<'_>) {
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
        // Also until the earliest wake, for that thread to run then.
        let mut slice_end = earliest(found.wake, slice);
        // Polling published to a wait already polled, or another CPU did, or
        // woke a broker thread: another may be due soon.
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
                end => break end,
            };
            match thread.suspended.get() {
                Suspended::InBroker(_) => {
                    match self.hand_off(cpu, claim, &thread, thread.slice_end.get()) {
                        HandOff::Resumed(again) => claim = again,
                        HandOff::Released { cpu_time } => break Slice::Released { cpu_time },
                        HandOff::Over(claim) => break Slice::Claimed(claim),
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
            if claim.is_stopped() || slice_end.is_some_and(|slice_end| now >= slice_end) {
                break Slice::Claimed(claim);
            }
        };
        // Including that slice, but not threads that were waiting.
        let cpu_time = match &end {
            Slice::Claimed(_) => thread.cpu_time.get(),
            Slice::Parked { cpu_time } | Slice::Released { cpu_time } => *cpu_time,
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
            Slice::Parked { .. } | Slice::Released { .. } => cpu::wake_idle(cpu),
        }
    }

    /// Runs the broker thread that `thread`'s broker call, which ended its run
    /// under `claim`, waits for, if it has yet to start, to `slice_end`,
    /// holding no claim. If it finished, retakes the claim before taking its
    /// stack back, which ends a `Futex` call's binding: so no other CPU's step
    /// ends that call first. Otherwise queues it, and tries the claim once.
    fn hand_off<'a>(
        &self,
        cpu: CpuId,
        claim: Claim<'a>,
        thread: &Arc<Thread>,
        slice_end: Option<Instant>,
    ) -> HandOff<'a> {
        let Some(work) = claim.broker.thread() else {
            return HandOff::Over(claim);
        };
        let start_at = self.platform.now();
        let at_call = thread.cpu_time.get();
        let caller = |ran| Account::Caller {
            broker_time: thread.broker_time.clone(),
            key: at_call.saturating_add(ran),
            ran,
        };
        if slice_end.is_some_and(|slice_end| start_at >= slice_end) {
            self.push_broker(BrokerRun::Start(work), caller(0));
            return HandOff::Over(claim);
        }
        // Carries its binding, if any: so a later call is another.
        let call = thread.suspended.get();
        let futex = matches!(call, Suspended::InBroker(BrokerCall::Futex { .. }));
        #[cfg(debug_assertions)]
        let slice_end = match self.hooks.broker_slice_end(start_at) {
            Some(capped) if slice_end.is_none_or(|slice_end| capped < slice_end) => {
                self.timer.arm_if_earlier(capped);
                Some(capped)
            }
            _ => slice_end,
        };
        self.arm_retake(thread, futex);
        let (broker, started) = work.start();
        let process = claim.process();
        drop(claim);
        self.counts[cpu.index()]
            .claims
            .fetch_add(1, Ordering::SeqCst);
        let (ran, slice_end) = broker.run(slice_end);
        let used = charged_since(self.platform, start_at);
        let (claim, held, briefly) = match ran {
            Ran::Finished(stack) => {
                thread.broker_time.fetch_add(used, Ordering::Relaxed);
                let held = self.hold_finished(thread, futex);
                let claim = process.claim_briefly();
                let briefly = claim.is_some();
                let claim = claim.or_else(|| held.map(|_| process.claim()));
                self.finish(started, stack);
                (claim, held, briefly)
            }
            Ran::Slept(broker) | Ran::Preempted(broker) => {
                self.push_broker(BrokerRun::Started(broker, started), caller(used));
                let held = self.hold_queued(thread, futex);
                let claim = process.try_claim();
                (claim.or_else(|| held.map(|_| process.claim())), held, false)
            }
        };
        let Some(claim) = claim else {
            return HandOff::Released {
                cpu_time: at_call.saturating_add(used),
            };
        };
        let other_end = held.map(|_| thread.slice_end.get());
        // Another CPU may have ended the call and run the thread on meanwhile:
        // then its slice end is that CPU's.
        let resumed = thread.running.get().is_none() && thread.suspended.get() == call;
        debug_assert!(
            resumed || !(briefly && futex) || process.is_dead(),
            "a `Futex` call whose thread finished in its handoff, which retook the claim, is \
             its caller's"
        );
        self.check_retake(held, resumed);
        if !resumed {
            debug_assert!(
                other_end.is_none_or(|end| thread.slice_end.get() == end),
                "a held handoff leaves its caller's slice end to the CPU that took its call on"
            );
            return HandOff::Over(claim);
        }
        thread.slice_end.set(slice_end);
        match claim.turn(thread) {
            Turn::Runnable => HandOff::Resumed(claim),
            _ => HandOff::Over(claim),
        }
    }

    /// Debug builds: arms `thread`'s latch, before any run of the caller.
    #[cfg(debug_assertions)]
    fn arm_retake(&self, thread: &Thread, futex: bool) {
        let event = match self.hooks.retake_case() {
            Some(RetakeHold::Handshake) if !futex => HOLD_RUN,
            Some(RetakeHold::PreemptedFutex) if futex => HOLD_RUN,
            Some(RetakeHold::PreemptedFutexRan) if futex => HOLD_RAN,
            _ => return,
        };
        thread.retake_hold.store(event, Ordering::SeqCst);
    }

    #[cfg(not(debug_assertions))]
    fn arm_retake(&self, _: &Thread, _: bool) {}

    /// Debug builds: holds a handoff whose thread finished, if asked to.
    #[cfg(debug_assertions)]
    fn hold_finished(&self, thread: &Thread, futex: bool) -> Option<RetakeHold> {
        let case = if futex {
            RetakeHold::Futex
        } else {
            RetakeHold::Handshake
        };
        if case == RetakeHold::Futex && self.hooks.retake_case() == Some(case) {
            thread.retake_hold.store(HOLD_LOOK, Ordering::SeqCst);
        }
        self.hold_retake(thread, case)
    }

    #[cfg(not(debug_assertions))]
    fn hold_finished(&self, _: &Thread, _: bool) -> Option<core::convert::Infallible> {
        None
    }

    /// Debug builds: holds a handoff whose thread was queued, if asked to.
    #[cfg(debug_assertions)]
    fn hold_queued(&self, thread: &Thread, futex: bool) -> Option<RetakeHold> {
        match self.hooks.retake_case() {
            Some(case @ (RetakeHold::PreemptedFutex | RetakeHold::PreemptedFutexRan)) if futex => {
                self.hold_retake(thread, case)
            }
            _ => None,
        }
    }

    #[cfg(not(debug_assertions))]
    fn hold_queued(&self, _: &Thread, _: bool) -> Option<core::convert::Infallible> {
        None
    }

    /// Debug builds: holds this handoff until another CPU latched `thread`.
    #[cfg(debug_assertions)]
    fn hold_retake(&self, thread: &Thread, case: RetakeHold) -> Option<RetakeHold> {
        if self.hooks.retake_case() != Some(case) {
            return None;
        }
        self.hooks
            .retake_case
            .compare_exchange(case as u8, 0, Ordering::SeqCst, Ordering::SeqCst)
            .ok()?;
        cpu::wake_idle(cpu::current());
        let start = self.platform.now();
        while thread.retake_hold.load(Ordering::SeqCst) != HOLD_DONE {
            assert!(
                self.platform.now().duration_since(&start) < Duration::from_secs(1),
                "another CPU looks at, or runs, a held handoff's caller ({case:?})"
            );
            core::hint::spin_loop();
        }
        thread.retake_hold.store(0, Ordering::SeqCst);
        Some(case)
    }

    /// Debug builds: checks how a handoff that was `held` left its caller.
    #[cfg(debug_assertions)]
    fn check_retake(&self, held: Option<RetakeHold>, resumed: bool) {
        if let Some(case) = held {
            assert_eq!(
                resumed,
                case == RetakeHold::Futex,
                "a held handoff ({case:?}) resumes its caller only if it finished a `Futex` call"
            );
            self.hooks.retaken.store(true, Ordering::SeqCst);
        }
    }

    #[cfg(not(debug_assertions))]
    fn check_retake(&self, _: Option<core::convert::Infallible>, _: bool) {}

    /// The end of a step that found no thread to run: false if nothing runs
    /// (see [`Self::is_idle`]); otherwise halts until the earliest wake,
    /// unless, on the boot CPU, it abandons the waits that nothing could end
    /// (see [`Self::abandon`]), which needs `claims` (the count as of the
    /// step's start, plus the claims it took): `None` if a claim was held as
    /// the step began (see [`Self::quiet`]).
    fn idle(&self, cpu: CpuId, found: Found<'_>, claims: Option<u64>) -> bool {
        let busy = found.blocked || found.skipped || found.brokers;
        if !busy && self.is_idle() {
            return false;
        }
        // One that came as the step ran, after its look.
        if self.poll_devices() {
            return true;
        }
        #[cfg(debug_assertions)]
        let found = Found {
            wake: if cpu == CpuId::BOOT && self.hooks.poll.load(Ordering::Relaxed) {
                earliest(
                    found.wake,
                    self.platform.now().checked_add(Duration::from_millis(1)),
                )
            } else {
                found.wake
            },
            ..found
        };
        if self.events.wait(found.wake) {
            return true;
        }
        // No deadline, and no device could end the halt: only another CPU
        // could end the waits. If none runs anything, nothing could.
        if !(found.forever.is_empty() || found.skipped || found.brokers) {
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
    /// with nothing to do (see [`Owned::is_quiescent`]), none is claimed, and
    /// no association thread exists.
    fn is_idle(&self) -> bool {
        let claims = self.claim_attempts();
        let queue = self.queue.lock();
        queue
            .processes
            .iter()
            .all(|process| !process.is_held() && process.is_quiescent())
            && self.associations_idle(&queue)
            && self.claim_attempts() == claims
    }

    /// Whether no association thread exists, and no inbox is bound. The source
    /// thread's runs end no process's quiescence.
    fn associations_idle(&self, queue: &RunQueue) -> bool {
        queue.running_associations == 0
            && self.broker.get().is_none_or(BrokerHandle::is_idle)
            && queue
                .brokers
                .iter()
                .all(|broker| broker.role == Role::Source)
    }

    /// Whether no broker thread runs or is due, but the source thread asleep.
    fn brokers_quiet(&self, queue: &RunQueue) -> bool {
        let now = self.platform.now();
        self.associations_idle(queue)
            && !queue.source_running
            && queue.brokers.iter().all(
                |broker| matches!(&broker.run, BrokerRun::Started(thread, _) if !thread.is_due(now)),
            )
    }

    /// Whether the processes are dead or quiescent, with no association thread.
    fn broker_drained(&self) -> bool {
        let queue = self.queue.lock();
        self.associations_idle(&queue)
            && queue.processes.iter().all(|process| process.is_quiescent())
    }

    /// Whether no other CPU ran anything since the count of claims was
    /// `claims` (with those the calling CPU's step took): none tried to take
    /// one since (but a CPU in the midst of taking one then, see
    /// [`Self::claim_attempts`]), none is held, no thread runs (in ring 3,
    /// without a claim, one may still end others' waits), and no broker thread
    /// runs or may. The step began with none held (see `Self::step`), so every
    /// claim since was counted, and the step's polls saw what those released
    /// before did; the step's own failed attempts (not in `claims`) make this
    /// fail. Teardown under no claim (e.g., a reap) publishes nothing: a death
    /// releases its references on its broker thread, whose runs this counts.
    fn quiet(&self, claims: u64) -> bool {
        let queue = self.queue.lock();
        !queue
            .processes
            .iter()
            .any(|process| process.is_held() || process.is_running())
            && self.brokers_quiet(&queue)
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

    /// How many times the CPUs tried to take a claim, or ran a broker thread:
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
        #[cfg(debug_assertions)]
        if let Some(kept) = &mut *self.hooks.reaped.lock() {
            kept.extend(reaped.iter().cloned());
        }
        // Outside the lock: a process's last reference releases its address
        // space.
        drop(reaped);
    }
}

/// How a thread's broker call went on (see [`Shared::hand_off`]).
enum HandOff<'a> {
    /// Its broker thread finished it: the thread resumes, under the claim.
    Resumed(Claim<'a>),
    /// See [`Slice::Released`].
    Released { cpu_time: u64 },
    /// The run is over, under the claim.
    Over(Claim<'a>),
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
            brokers: self.brokers,
            forever: self.forever,
            skipped: self.skipped,
        }
    }
}

impl<'a> Found<'a> {
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
        if claim.broker.has_failed() {
            claim.kill("broker association failed");
        }
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
                    self.wake = earliest(self.wake, wake);
                    if wake.is_none() {
                        self.forever.push((
                            Arc::downgrade(process),
                            thread.clone(),
                            thread.suspended.get(),
                        ));
                    }
                }
                Turn::InBroker => self.brokers = true,
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
    /// Its broker call waits for its broker thread.
    InBroker,
}

impl Inner {
    /// If this CPU was notified (a blocked thread's wait may have ended),
    /// ends the slice of `thread`, which runs on it: at once if it is the
    /// only CPU online, else within [`NOTIFIED`]; at once if it is to
    /// reschedule (see [`cpu::take_resched`]).
    pub(crate) fn take_notified(&self, thread: &Thread) {
        let resched = cpu::take_resched();
        let notified = cpu::take_notified();
        if resched || (notified && cpu::online_count() == 1) {
            self.end_slice_by(thread, Duration::ZERO);
        } else if notified {
            self.end_slice_by(thread, NOTIFIED);
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
        // Not one this CPU parked, whose run no step finished yet.
        if let Some(thread) = self
            .threads
            .borrow()
            .iter()
            .find(|thread| thread.cpu_to_interrupt() == Some(cpu))
        {
            self.end_slice_by(thread, QUANTUM);
        }
    }

    /// Ends `thread`'s slice `duration` from now, at the latest.
    fn end_slice_by(&self, thread: &Thread, duration: Duration) {
        let slice_end = end_by(thread.slice_end.get(), self.platform.now(), duration);
        thread.slice_end.set(Some(slice_end));
    }

    /// `thread`'s [`Turn`]; ends its wait first, if it can.
    fn turn(&self, thread: &Thread) -> Turn {
        if thread.running.get().is_some() {
            return Turn::Running;
        }
        thread.fold_broker_time();
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
        let wait = match thread.suspended.get() {
            Suspended::InBroker(BrokerCall::Futex { binding, then }) => {
                #[cfg(debug_assertions)]
                latch_retake_hold(thread, HOLD_LOOK);
                if !self.broker.has_ended(binding) {
                    return Turn::InBroker;
                }
                if then.is_none() {
                    thread.suspended.set(Suspended::Woken(Ok(())));
                }
                then
            }
            Suspended::InBroker(BrokerCall::Handshake { slot }) => {
                if !self.broker.has_handshake_reply() {
                    return Turn::InBroker;
                }
                thread.suspended.set(Suspended::Handshaken { slot });
                None
            }
            Suspended::Waiting(wait) => Some(wait),
            _ => None,
        };
        let woken = match (wait, thread.suspended.get()) {
            (Some(wait), _) => match self.broker.poll_wait(&wait) {
                WaitState::Blocked { wake } => {
                    thread.suspended.set(Suspended::Waiting(wait));
                    return Turn::Blocked(wake);
                }
                WaitState::Ended(Ok(())) => Some(Ok(())),
                WaitState::Ended(Err(EnterError::Status(status))) => Some(Err(status)),
                WaitState::Ended(Err(EnterError::Failed)) => {
                    self.kill("broker association failed");
                    return Turn::Stopped;
                }
            },
            (None, Suspended::Futex(wait)) => match self.poll_futex(thread, &wait) {
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
        #[cfg(debug_assertions)]
        latch_retake_hold(thread, HOLD_RUN);
        let space = claim.activate_thread(thread);
        let running = Running::new(claim, thread);
        let run_end = {
            let mut ctx = thread.ctx_mut();
            let mut state = thread.user_state_mut();
            let (ctx, state) = (&mut *ctx, &mut *state);
            // Safety: the thread runs on this CPU alone (see
            // `Thread::running`), where no other thread runs; `ctx` is its
            // context.
            unsafe {
                if new {
                    litebox_platform_vm_kernel::run_thread_ref(&running, ctx, state)
                } else if resume {
                    litebox_platform_vm_kernel::resume_thread_ref(&running, ctx, state)
                } else {
                    litebox_platform_vm_kernel::reenter_thread_ref(&running, ctx, state)
                }
            }
        };
        let fs_base = space.end(matches!(thread.suspended.get(), Suspended::InBroker(_)));
        let claim = match running.end(run_end) {
            Ended::Claimed(claim) => claim,
            Ended::Unclaimed(unclaimed) => {
                if let Unclaimed::GaveUp(_) = unclaimed {
                    self.counts[cpu.index()]
                        .parks
                        .fetch_add(1, Ordering::Relaxed);
                }
                let used = charged_since(platform, start);
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
        #[cfg(debug_assertions)]
        latch_retake_hold(thread, HOLD_RAN);
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
    fn a_kernel_threads_run_ends_at_its_slice_end_or_for_its_cpus_marks() {
        let at = Instant::from_nanos;
        let notified_ns = u64::try_from(NOTIFIED.as_nanos()).unwrap();
        let grace = u64::try_from(GRACE.as_nanos()).unwrap();
        let (safe, interrupt) = (Point::SafePoint, Point::Interrupt);
        let run_on =
            |end: Option<u64>, arm: Option<u64>| (Check::Continue(end.map(at)), arm.map(at));
        let marks = Marks::default();
        let alone = Marks {
            alone: true,
            ..marks
        };
        let resched = Marks {
            resched: true,
            ..marks
        };
        let notified = Marks {
            notified: true,
            ..marks
        };
        let notified_alone = Marks {
            alone: true,
            ..notified
        };
        assert_eq!(
            check_run(safe, at(100), Some(at(200)), GRACE, marks),
            run_on(Some(200), None)
        );
        assert_eq!(
            check_run(interrupt, at(100), Some(at(200)), GRACE, marks),
            run_on(Some(200), Some(200 + grace))
        );
        assert_eq!(
            check_run(safe, at(100), None, GRACE, alone),
            run_on(None, None)
        );
        assert_eq!(
            check_run(safe, at(200), Some(at(200)), GRACE, marks),
            (Check::Preempt, None)
        );
        assert_eq!(
            check_run(interrupt, at(200), Some(at(200)), GRACE, marks),
            run_on(Some(200), Some(200 + grace))
        );
        assert_eq!(
            check_run(interrupt, at(200 + grace), Some(at(200)), GRACE, marks),
            (Check::Preempt, None)
        );
        assert_eq!(
            check_run(safe, at(100), None, GRACE, resched),
            (Check::Preempt, None)
        );
        assert_eq!(
            check_run(interrupt, at(100), None, GRACE, resched),
            run_on(Some(100), Some(100 + grace))
        );
        assert_eq!(
            check_run(safe, at(100), None, GRACE, notified_alone),
            (Check::Preempt, None)
        );
        for slice_end in [None, Some(at(100 + 100 * grace))] {
            assert_eq!(
                check_run(safe, at(100), slice_end, GRACE, notified),
                run_on(Some(100 + notified_ns), Some(100 + notified_ns + grace))
            );
        }
        assert_eq!(
            check_run(safe, at(100), Some(at(150)), GRACE, notified),
            run_on(Some(150), None)
        );
        for (slice_end, end) in [(None, 100), (Some(at(200)), 100), (Some(at(50)), 50)] {
            assert_eq!(end_by(slice_end, at(100), Duration::ZERO), at(end));
            assert_eq!(
                check_run(safe, at(120), Some(at(end)), GRACE, marks),
                (Check::Preempt, None)
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

    #[test]
    fn a_callers_broker_thread_counts_as_its_kernel_half() {
        let caller = Thread::main(crate::layout::UPCALL_STACK);
        caller.cpu_time.set(5 * QUANTUM_NANOS);
        let mut account = Account::Caller {
            broker_time: caller.broker_time.clone(),
            key: caller.cpu_time.get(),
            ran: 0,
        };
        account.charge(charged(3 * QUANTUM_NANOS / 2));
        assert_eq!(account.counted(0), 6 * QUANTUM_NANOS);
        assert_eq!(account.counted(20 * QUANTUM_NANOS), 19 * QUANTUM_NANOS);
        account.charge(QUANTUM_NANOS);
        assert_eq!(account.counted(20 * QUANTUM_NANOS), 20 * QUANTUM_NANOS);
        assert_eq!(account.counted(10 * QUANTUM_NANOS), 20 * QUANTUM_NANOS);
        assert_eq!(account.key(), 20 * QUANTUM_NANOS);
        account.finish();
        assert_eq!(caller.cpu_time.get(), 5 * QUANTUM_NANOS);
        caller.fold_broker_time();
        assert_eq!(caller.cpu_time.get(), 7 * QUANTUM_NANOS);
        caller.fold_broker_time();
        assert_eq!(caller.cpu_time.get(), 7 * QUANTUM_NANOS, "folded once");
    }

    #[test]
    fn a_broker_thread_of_its_own_counts_its_runs_and_is_floored() {
        let mut account = Account::Own(0);
        account.charge(charged(2 * QUANTUM_NANOS));
        assert_eq!(
            account.counted(0),
            QUANTUM_NANOS,
            "a run is charged a slice at most"
        );
        assert_eq!(account.counted(10 * QUANTUM_NANOS), 9 * QUANTUM_NANOS);
        assert_eq!(account.counted(0), 9 * QUANTUM_NANOS);
        account.charge(QUANTUM_NANOS);
        assert_eq!(account.counted(0), 10 * QUANTUM_NANOS);
        account.finish();
    }
}
