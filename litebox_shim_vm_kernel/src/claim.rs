// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Per-process ownership: a runner process's [`Inner`] belongs to at most one
//! CPU at a time, the one holding its claim, so its `Cell`s and `RefCell`s
//! need no other synchronization. Whoever runs one of its threads, polls its
//! waits, delivers its requests, spawns its launched children, or runs a
//! worker for it holds the claim. A process clone not adopted yet is claimed
//! only by its parent's holder (see `fork`).
//!
//! The scheduler only tries to claim ([`Owned::try_claim`]). Services wait for
//! a claim ([`Owned::claim`]) holding none, so no two CPUs ever wait for each
//! other's claims; meanwhile, the boot CPU resumes its worker, which the
//! holder may wait for, and takes interrupts.
//!
//! A process's address space is current only on the CPU that holds its claim
//! (see [`Claim`]'s `Drop`): its user mappings are in at most one CPU's TLB,
//! so local flushes suffice (see `litebox_platform_vm_kernel`).
//!
//! Each release leaves lock-free mirrors of the process's state (e.g.,
//! [`Owned::is_stopped`]), and wakes the CPUs that may now have work: the
//! other idle ones if the process has work another may take; those that found
//! it claimed; and the boot CPU if it stopped, or is quiescent.

use crate::Inner;
use crate::sched::bit;
use alloc::sync::Arc;
use core::cell::Cell;
use core::marker::PhantomData;
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use litebox_platform_vm_kernel::cpu::{self, CpuId};
use litebox_platform_vm_kernel::{AddressSpaceId, LOCK_WARNING};

/// [`Owned::worker`]: no CPU's.
const NO_CPU: u8 = u8::MAX;

/// A runner process's [`Inner`], behind its claim.
pub(crate) struct Owned {
    /// Its place in the round-robin order (see `sched`): creation order.
    pub(crate) seq: u64,
    /// Its scheduler's count of the attempts, by any CPU, to take a claim of
    /// any of its processes (see `sched`): each counted before it is made,
    /// taken or not.
    claims: Arc<AtomicU64>,
    held: AtomicBool,
    /// Bit `i`: CPU `i` found it held, and skipped it (see
    /// [`Self::try_claim`]); the release wakes those.
    contended: AtomicU64,
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
// before releasing it. References to its threads held past a claim (in
// `sched`) only count references, atomically. What other CPUs reach
// otherwise is thread-safe itself: the parts of `inner` it shares with the
// broker (e.g., its readiness) and the platform, and its `platform`, which
// never changes (e.g., for a claim wait's clock); the rest of `Owned` is
// atomic. Its last reference drops it, with exclusive access.
unsafe impl Send for Owned {}
// Safety: as for `Send`.
unsafe impl Sync for Owned {}

impl Owned {
    /// Published to the other CPUs, so its address space must not be current
    /// (see `Inner::spawn`). A process clone not adopted yet is quiescent.
    pub(crate) fn new(inner: Inner, seq: u64, claims: Arc<AtomicU64>) -> Self {
        Self {
            seq,
            claims,
            held: AtomicBool::new(false),
            contended: AtomicU64::new(0),
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
    /// (A claim won on a retry keeps the caller's bit in `contended`: its own
    /// release then wakes the caller too, harmlessly.)
    pub(crate) fn try_claim(self: &Arc<Self>) -> Option<Claim<'_>> {
        loop {
            if let Some(claim) = self.take() {
                return Some(claim);
            }
            // Before rechecking: either the holder's release sees it, or this
            // sees the release.
            self.contended
                .fetch_or(bit(cpu::current()), Ordering::SeqCst);
            if self.held.load(Ordering::SeqCst) {
                return None;
            }
        }
    }

    /// The claim, once another CPU releases it, calling `waiting` meanwhile,
    /// now and then (see `sched::Scheduler::claim`), and taking interrupts
    /// (see [`cpu::relax`]). Never while holding a claim. If the claim stays
    /// held for [`LOCK_WARNING`] from the last release seen, warns, once, as
    /// it may be a deadlock (e.g., the holder waits for what the calling CPU
    /// holds), and waits on: a claim is held across a whole work (all its
    /// round trips, and its waits for other CPUs' locks), and this wait also
    /// counts its own worker's time (in `waiting`).
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
            while self.held.load(Ordering::Relaxed) {
                if !warned && platform.now() >= deadline {
                    litebox_util_log::warn!(
                        waited:? = LOCK_WARNING;
                        "still waiting for a process's claim: a deadlock? (see `claim`)"
                    );
                    warned = true;
                }
                waiting();
                for _ in 0..SPINS {
                    if !self.held.load(Ordering::Relaxed) {
                        break;
                    }
                    cpu::relax();
                }
            }
        }
    }

    /// The claim, if no CPU holds it: an attempt, counted first, taken or not
    /// (see [`Self::claims`]).
    fn take(self: &Arc<Self>) -> Option<Claim<'_>> {
        self.claims.fetch_add(1, Ordering::SeqCst);
        if self
            .held
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::Relaxed)
            .is_ok()
        {
            return Some(Claim::new(self));
        }
        None
    }

    /// # Safety
    ///
    /// The calling CPU must hold the claim, for as long as it uses the result
    /// (e.g., the worker serving the process, which runs only under it).
    pub(crate) unsafe fn claimed(&self) -> &Inner {
        &self.inner
    }

    /// Whether the process waits for a request, or is dead.
    pub(crate) fn is_stopped(&self) -> bool {
        self.stopped.load(Ordering::SeqCst)
    }

    /// Stopped, or a process clone not adopted yet, which runs nothing (see
    /// `fork`), and nothing to do for it: no worker suspended serving it,
    /// and, unless dead, nothing submitted to serve. Only a service's call
    /// (e.g., `Process::submit`), or, for a clone, its adoption, changes that.
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
        self.held.load(Ordering::SeqCst)
    }

    /// [`Inner::worker`]: only that CPU is to claim it.
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

/// The calling CPU owns the process until this drops; see the module docs.
pub(crate) struct Claim<'a> {
    owned: &'a Arc<Owned>,
    /// See [`Self::share`].
    share: Cell<bool>,
    /// Not `Send`: released by the CPU that took it, whose address space its
    /// `Drop` checks.
    _cpu: PhantomData<*const ()>,
}

impl<'a> Claim<'a> {
    fn new(owned: &'a Arc<Owned>) -> Self {
        Self {
            owned,
            share: Cell::new(false),
            _cpu: PhantomData,
        }
    }

    pub(crate) fn process(&self) -> &'a Arc<Owned> {
        self.owned
    }

    /// The process has work another CPU may take (e.g., a runnable thread):
    /// the release wakes the other idle CPUs.
    pub(crate) fn share(&self) {
        self.share.set(true);
    }

    /// See [`Owned::runnable`].
    pub(crate) fn set_runnable(&self, cpu_time: Option<u64>) {
        self.owned
            .runnable
            .store(cpu_time.unwrap_or(u64::MAX), Ordering::Relaxed);
    }
}

impl core::ops::Deref for Claim<'_> {
    type Target = Inner;

    fn deref(&self) -> &Inner {
        &self.owned.inner
    }
}

impl Drop for Claim<'_> {
    /// Leaves the kernel's address space current, in place of whichever was
    /// (this process's, or another's whose claim the CPU still holds, which
    /// is made current again to run), updates the mirrors, then releases the
    /// claim, and wakes the CPUs that may have work.
    fn drop(&mut self) {
        let owned = self.owned;
        let inner = &owned.inner;
        if inner.platform.current_address_space() != AddressSpaceId::KERNEL {
            // Safety: the kernel holds no references into user memory.
            unsafe { inner.platform.switch_address_space(AddressSpaceId::KERNEL) }
                .expect("the kernel address space always exists");
        }
        let stopped = inner.is_stopped();
        let dead = inner.is_dead();
        let worker = inner.worker.get();
        let quiescent = (stopped || inner.is_cloned())
            && worker.is_none()
            && (dead || !inner.broker.has_submitted());
        let needs_serving = !dead && worker.is_none() && inner.broker.has_submitted();
        let was_stopped = owned.stopped.swap(stopped, Ordering::SeqCst);
        owned.dead.store(dead, Ordering::SeqCst);
        owned.quiescent.store(quiescent, Ordering::SeqCst);
        owned.needs_serving.store(needs_serving, Ordering::SeqCst);
        owned.worker.store(
            worker.map_or(NO_CPU, |cpu| {
                u8::try_from(cpu.index()).expect("CPU indices fit a byte")
            }),
            Ordering::SeqCst,
        );
        owned.held.store(false, Ordering::SeqCst);
        if self.share.get() {
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
