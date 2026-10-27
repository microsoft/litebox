// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-process ownership: a runner process's [`Inner`] belongs to at most one
//! CPU at a time, the one holding its claim, so its `Cell`s and `RefCell`s
//! need no other synchronization. Whoever polls its waits, delivers its
//! requests, spawns its launched children, runs a worker for it, or hands
//! one of its threads to a CPU's run holds the claim, as does each kernel
//! entry of its running threads, which run in ring 3 without it, several at
//! once (see `Running`). A process clone not adopted yet is claimed only by
//! its parent's holder (see `fork`).
//!
//! The scheduler only tries to claim ([`Owned::try_claim`]), but spins
//! briefly, holding none, for the process its CPU's worker serves; and an
//! entry spins for the claim only briefly ([`Owned::claim_briefly`]), else
//! its CPU parks the thread (see `sched`). Only services wait for a claim
//! ([`Owned::claim`]), holding none, so no two CPUs ever wait for each
//! other's claims; meanwhile, they resume their own worker, which the holder
//! may wait for, and take interrupts.
//!
//! Each release leaves lock-free mirrors of the process's state (e.g.,
//! [`Owned::is_stopped`]), and wakes the CPUs that may now have work: the
//! other idle ones if the process has work another may take; those that found
//! it claimed; and the boot CPU if it stopped, or is quiescent.

use crate::Inner;
use crate::sched::{CpuCounts, bit};
use crate::thread::Thread;
use alloc::sync::Arc;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU32, AtomicU64, Ordering};
use core::time::Duration;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId, MAX_CPUS};
use litebox_platform_vm_kernel::{Instant, LOCK_WARNING, VmKernel};

/// [`Owned::worker`] and [`Owned::holder`]: no CPU's.
const NO_CPU: u8 = u8::MAX;

/// At most how long an entry spins for its process's claim.
///
/// Past it, the entry gives up, and its CPU parks the thread
/// ([`Owned::claim_briefly`]). It is about what the park would cost the thread
/// (a step to claim the process, finish the run, and run the thread again),
/// and longer than the claim's usual holds, even a few in a row as other CPUs
/// take it first: other entries' (e.g., page-table changes, whose TLB
/// shootdowns wait for the other CPUs) and steps'. The CPU runs nothing else
/// meanwhile, where a park would let it run another thread (e.g., another
/// process's), and the spin counts as the thread's CPU time. A step resuming
/// its CPU's worker gives up likewise, and retries within `NOTIFIED` (see
/// `sched`).
const ENTRY_SPIN: Duration = Duration::from_micros(200);

/// A runner process's [`Inner`], behind its claim.
pub(crate) struct Owned {
    /// Its place in the round-robin order (see `sched`): creation order.
    pub(crate) seq: u64,
    /// Its scheduler's counts, by CPU index (see `sched`), where each CPU
    /// counts its attempts to take a claim of any of its processes: each
    /// before it is made, taken or not.
    counts: Arc<[CpuCounts; MAX_CPUS]>,
    /// The CPU holding the claim's index, or [`NO_CPU`] if none holds it (see
    /// [`Self::claimed`]).
    holder: AtomicU8,
    /// Bit `i`: CPU `i` found it held, and skipped it (see
    /// [`Self::try_claim`]); the release wakes those.
    contended: AtomicU64,
    /// How many of its threads run (see [`Self::is_running`]): changed under
    /// the claim.
    running: AtomicU32,
    /// Mirrors, as of the last release.
    stopped: AtomicBool,
    quiescent: AtomicBool,
    dead: AtomicBool,
    /// See [`Self::needs_serving`].
    needs_serving: AtomicBool,
    /// [`Inner::worker`]'s index, or [`NO_CPU`].
    worker: AtomicU8,
    /// See [`Self::runnable`].
    runnable: AtomicU64,
    inner: Inner,
}

// Safety: `inner`, whose `Cell`s, `RefCell`s and threads are not
// thread-safe, is reached only through a `Claim` (or `claimed`, under one),
// so by one CPU at a time: taking a claim acquires what its last holder did
// before releasing it. The exception is a running thread's `ctx` and
// `user_state`, which only its CPU touches, without the claim, from the claim
// that hands it the thread until its run ends (see `Thread::ctx_mut`); a run
// that ends without the claim leaves the rest to the claim's next holder
// through `Thread::parked`, a lock, which orders the two. References to its
// threads held past a claim (in `sched`) only count references, atomically.
// What other CPUs reach otherwise is thread-safe itself: the parts of
// `inner` it shares with the broker (e.g., its readiness) and the platform,
// and its `platform`, which never changes (e.g., for a claim wait's clock);
// the rest of `Owned` is atomic. Its last reference drops it, with exclusive
// access.
unsafe impl Send for Owned {}
// Safety: as for `Send`.
unsafe impl Sync for Owned {}

impl Owned {
    /// A process clone not adopted yet is quiescent.
    pub(crate) fn new(inner: Inner, seq: u64, counts: Arc<[CpuCounts; MAX_CPUS]>) -> Self {
        Self {
            seq,
            counts,
            holder: AtomicU8::new(NO_CPU),
            contended: AtomicU64::new(0),
            running: AtomicU32::new(0),
            stopped: AtomicBool::new(false),
            quiescent: AtomicBool::new(inner.is_cloned()),
            dead: AtomicBool::new(false),
            needs_serving: AtomicBool::new(false),
            worker: AtomicU8::new(NO_CPU),
            runnable: AtomicU64::new(u64::MAX),
            inner,
        }
    }

    /// The claim, unless another CPU holds it; then its release wakes the
    /// calling CPU, so that it need not poll the process again until then.
    /// At most two attempts, so no spin. (One taken on the second keeps the
    /// caller's bit in `contended`, unless a release woke it since: its own
    /// release then wakes it, as the failed first attempt fails its step's
    /// checks that nothing ran; see `sched`.)
    pub(crate) fn try_claim(self: &Arc<Self>) -> Option<Claim<'_>> {
        if let Some(claim) = self.take() {
            return Some(claim);
        }
        // Before rechecking: either the holder's release sees it, or this
        // sees the release.
        self.contended
            .fetch_or(bit(cpu::current()), Ordering::SeqCst);
        if self.is_held() {
            return None;
        }
        // Released since: once more. Lost, another CPU took it after the
        // recheck, and its release, or one before, sees the bit.
        self.take()
    }

    /// The claim, once another CPU releases it.
    ///
    /// Meanwhile, calls `waiting` now and then (see
    /// `sched::Scheduler::claim`), and takes interrupts (see [`cpu::relax`]).
    /// Never while holding a claim. If the claim stays held for
    /// [`LOCK_WARNING`] from the last release seen, warns, once, as it may be
    /// a deadlock (e.g., the holder waits for what the calling CPU holds), and
    /// waits on: a claim is held across a whole work (all its round trips, and
    /// its waits for other CPUs' locks), and this wait also counts its own
    /// worker's time (in `waiting`). Not fair: other CPUs may take the claim
    /// first any number of times. But services claim processes that wait for a
    /// request or are dead (see [`Self::is_stopped`]), whose threads end their
    /// runs at their next entries (see `Running`): so only steps, workers and
    /// those last entries take it meanwhile, not a stream of entries.
    pub(crate) fn claim(self: &Arc<Self>, mut waiting: impl FnMut()) -> Claim<'_> {
        /// Spins between calls of `waiting`.
        const SPINS: u32 = 1 << 10;
        let platform = self.inner.platform;
        let mut warned = false;
        loop {
            if let Some(claim) = self.take() {
                return claim;
            }
            let deadline = platform
                .now()
                .checked_add(LOCK_WARNING)
                .expect("the clock is far from overflowing");
            while self.holder.load(Ordering::Relaxed) != NO_CPU {
                if !warned && platform.now() >= deadline {
                    litebox_util_log::warn!(
                        waited:? = LOCK_WARNING;
                        "still waiting for a process's claim: a deadlock? (see `claim`)"
                    );
                    warned = true;
                }
                waiting();
                for _ in 0..SPINS {
                    if self.holder.load(Ordering::Relaxed) == NO_CPU {
                        break;
                    }
                    cpu::relax();
                }
            }
        }
    }

    /// For an entry of a running thread (see `Running`), or a step resuming
    /// its CPU's worker (see `sched`), holding no claim: the claim, unless
    /// this CPU cannot take it within [`ENTRY_SPIN`] (one budget, however
    /// often the claim changes hands), meanwhile taking interrupts (see
    /// [`cpu::relax`]). An entry cannot wait longer: the holder may wait for
    /// this CPU's suspended worker, which the CPU resumes only outside the
    /// thread's run (see `litebox_platform_vm_kernel::worker`).
    pub(crate) fn claim_briefly(self: &Arc<Self>) -> Option<Claim<'_>> {
        if let Some(claim) = self.take() {
            return Some(claim);
        }
        let platform = self.inner.platform;
        let deadline = platform
            .now()
            .checked_add(ENTRY_SPIN)
            .unwrap_or(Instant::from_nanos(u64::MAX));
        loop {
            if self.holder.load(Ordering::Relaxed) == NO_CPU
                && let Some(claim) = self.take()
            {
                return Some(claim);
            }
            // Also once it saw the claim free, but lost it.
            if platform.now() >= deadline {
                return None;
            }
            cpu::relax();
        }
    }

    /// The claim, if no CPU holds it: an attempt, counted first, taken or not
    /// (see [`Self::counts`]).
    fn take(self: &Arc<Self>) -> Option<Claim<'_>> {
        let cpu = cpu::current();
        self.counts[cpu.index()]
            .claims
            .fetch_add(1, Ordering::SeqCst);
        self.holder
            .compare_exchange(
                NO_CPU,
                index(Some(cpu)),
                Ordering::SeqCst,
                Ordering::Relaxed,
            )
            .ok()
            .map(|_| Claim::new(self))
    }

    /// The process, if the calling CPU holds the claim (as [`Self::holder`]
    /// alone tells), else `None`.
    ///
    /// # Safety
    ///
    /// The calling CPU need not hold the claim; but if it gets the process, it
    /// must keep the claim for as long as it uses it (e.g., the worker serving
    /// the process, which runs only under it).
    pub(crate) unsafe fn claimed(&self) -> Option<&Inner> {
        // Only the holder stores its index there, as it takes the claim, and
        // clears it to release it.
        (self.holder.load(Ordering::Relaxed) == index(Some(cpu::current()))).then_some(&self.inner)
    }

    /// Whether the process waits for a request, or is dead.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// The process's platform, which never changes, so needs no claim (e.g.,
    /// for the clock).
    pub(crate) fn platform(&self) -> &'static VmKernel {
        self.inner.platform
    }

    /// Stopped, or a process clone not adopted yet, which runs nothing (see
    /// `fork`), and nothing to do for it: no thread running, no worker
    /// suspended serving it, and, unless dead, nothing submitted to serve.
    /// Only a service's call (e.g., `Process::submit`), or, for a clone, its
    /// adoption, changes that.
    pub(crate) fn is_quiescent(&self) -> bool {
        self.quiescent.load(Ordering::SeqCst)
    }

    pub(crate) fn is_dead(&self) -> bool {
        self.dead.load(Ordering::SeqCst)
    }

    /// Whether a worker may have to serve what the process submitted: it is
    /// not dead, no worker is suspended serving it, and its threads' calls may
    /// have published requests since it was last served (see `sched`). Only
    /// its claim's holder changes that, and its release publishes it.
    pub(crate) fn needs_serving(&self) -> bool {
        self.needs_serving.load(Ordering::SeqCst)
    }

    /// Whether a CPU holds the claim.
    pub(crate) fn is_held(&self) -> bool {
        self.holder.load(Ordering::SeqCst) != NO_CPU
    }

    /// Whether one of its threads runs (see [`Thread::running`]): in ring 3,
    /// without the claim, it may still end other threads' waits.
    pub(crate) fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst) != 0
    }

    /// [`Inner::worker`]: only that CPU resumes it.
    pub(crate) fn worker(&self) -> Option<CpuId> {
        CpuId::new(usize::from(self.worker.load(Ordering::SeqCst)))
    }

    /// The least CPU time of its runnable threads (see `sched`) when last
    /// polled, if any: a lower bound, as CPU time only grows.
    pub(crate) fn runnable(&self) -> Option<u64> {
        let cpu_time = self.runnable.load(Ordering::Relaxed);
        (cpu_time != u64::MAX).then_some(cpu_time)
    }
}

/// `cpu`'s index, or [`NO_CPU`], for [`Owned`]'s atomics.
fn index(cpu: Option<CpuId>) -> u8 {
    cpu.map_or(NO_CPU, |cpu| {
        u8::try_from(cpu.index()).expect("CPU indices fit a byte")
    })
}

/// The calling CPU owns the process until this drops; see the module docs.
pub(crate) struct Claim<'a> {
    owned: &'a Arc<Owned>,
    /// Not `Send`: released by the CPU that took it (see [`Owned::claimed`]).
    _cpu: PhantomData<*const ()>,
}

impl<'a> Claim<'a> {
    fn new(owned: &'a Arc<Owned>) -> Self {
        Self {
            owned,
            _cpu: PhantomData,
        }
    }

    pub(crate) fn process(&self) -> &'a Arc<Owned> {
        self.owned
    }

    /// See [`Owned::runnable`].
    pub(crate) fn set_runnable(&self, cpu_time: Option<u64>) {
        self.owned
            .runnable
            .store(cpu_time.unwrap_or(u64::MAX), Ordering::Relaxed);
    }

    /// Records the CPU `thread` runs on, or that it no longer runs (see
    /// [`Thread::running`] and [`Owned::is_running`]).
    pub(crate) fn set_running(&self, thread: &Thread, cpu: Option<CpuId>) {
        match (thread.running.replace(cpu), cpu) {
            (None, Some(_)) => {
                self.owned.running.fetch_add(1, Ordering::SeqCst);
            }
            (Some(_), None) => {
                self.owned.running.fetch_sub(1, Ordering::SeqCst);
            }
            (None, None) => {}
            // In release builds too: CPU `old` runs the thread, or parked it,
            // and two CPUs would then run it on its `ctx` and `user_state`
            // (see `Thread::ctx_mut`).
            (Some(old), Some(new)) => {
                panic!(
                    "thread {} handed to CPU {new}, but CPU {old} runs it",
                    thread.id
                )
            }
        }
    }
}

impl core::ops::Deref for Claim<'_> {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.owned.inner
    }
}

impl Drop for Claim<'_> {
    /// Updates the mirrors, then releases the claim, and wakes the CPUs that
    /// may have work. On every kernel entry of a running thread: keep it
    /// short.
    fn drop(&mut self) {
        let owned = self.owned;
        let inner = &owned.inner;
        let stopped = inner.is_stopped();
        let dead = inner.is_dead();
        let worker = inner.worker.get();
        let quiescent = (stopped || inner.is_cloned())
            && worker.is_none()
            && !owned.is_running()
            && (dead || !inner.broker.has_submitted());
        let needs_serving = !dead && worker.is_none() && inner.broker.has_submitted();
        let was_stopped = owned.stopped.swap(stopped, Ordering::SeqCst);
        owned.dead.store(dead, Ordering::SeqCst);
        owned.quiescent.store(quiescent, Ordering::SeqCst);
        owned.needs_serving.store(needs_serving, Ordering::SeqCst);
        owned.worker.store(index(worker), Ordering::SeqCst);
        let share = inner.shared.take();
        owned.holder.store(NO_CPU, Ordering::SeqCst);
        if share {
            cpu::wake_idle(cpu::current());
        }
        let contended = owned.contended.swap(0, Ordering::SeqCst);
        if contended != 0 {
            cpu::online()
                .filter(|&cpu| contended & bit(cpu) != 0)
                .for_each(cpu::wake);
        }
        if (stopped && !was_stopped) || quiescent {
            // For what its services wait for (see `Scheduler::run_until`).
            cpu::wake(CpuId::BOOT);
        }
    }
}
