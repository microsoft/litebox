// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The psynch calls behind pthread mutexes, condition variables and rwlocks
//! (BSD 297-309 and 312), after libpthread's `kern/kern_synch.c`.
//!
//! Userspace keeps each object's state in sequence words: L counts lock (or
//! wait) attempts, U unlocks (or signals), S returns from the kernel, each in
//! units of `PTHRW_INC` above a few state bits. A thread enters the kernel
//! with its view of the words; the kernel keeps one wait queue (`ksyn_wait_
//! queue`) per object, ordered by the sequence each waiter took, and records
//! an unlock or signal that arrives before its waiter as a prepost.
//!
//! Every queue lives in one table under one lock, so each call's queue
//! updates are atomic. A waiter leaves its queue only under that lock, either
//! taken by a waker that grants it a value or withdrawn when its wait ends;
//! a wakeup therefore never finds its waiter gone (`KERN_NOT_WAITING`), and
//! XNU's bookkeeping for such failed wakeups (`kw_intr`) has no state here.
//! Owners and turnstiles only steer priority inheritance, which the host
//! scheduler does not model; the mutex owner is still tracked.

#![expect(
    clippy::similar_names,
    reason = "the sequence words keep kern_synch.c's names (cgen, csgen, cugen, mgen, mugen)"
)]

use crate::{
    ShimPlatform, Task, ThreadId,
    syscalls::cancel::TestCancel,
    thread::TASK_THREADMAX,
    wait::{WaitResult, Waiter},
};
use alloc::{collections::BTreeMap, collections::VecDeque, sync::Arc, vec::Vec};
use core::ops::Range;
use core::sync::atomic::{AtomicU32, Ordering};
use litebox::{sync::MutexGuard, utils::TruncateExt};
use litebox_common_macos::{errno::Errno, syscall::PsynchRwOperation};

const PTHRW_COUNT_SHIFT: u32 = 8;
const PTHRW_INC: u32 = 1 << PTHRW_COUNT_SHIFT;
const PTHRW_BIT_MASK: u32 = PTHRW_INC - 1;
const PTHRW_COUNT_MASK: u32 = !PTHRW_BIT_MASK;
const PTHRW_MAX_READERS: u32 = PTHRW_COUNT_MASK;

/// L word bits.
const PTH_RWL_KBIT: u32 = 0x01;
const PTH_RWL_EBIT: u32 = 0x02;
const PTH_RWL_WBIT: u32 = 0x04;
const PTH_RWL_MTX_WAIT: u32 = 0x20;
const PTH_RWL_MBIT: u32 = 0x40;
const PTHRW_RWL_INIT: u32 = 0x80;

/// S word bits.
const PTH_RWS_SBIT: u32 = 0x01;
const PTH_RWS_CV_CBIT: u32 = PTH_RWS_SBIT;
const PTH_RWS_CV_PBIT: u32 = 0x02;
const PTH_RWS_CV_MBIT: u32 = PTH_RWL_MBIT;
const PTHRW_RWS_SAVEMASK: u32 = 0x04;
const PTHRW_RWS_INIT: u32 = PTH_RWS_SBIT;

/// Mutex option bits the kernel reads from `flags`.
const PTHREAD_PSHARED_FLAGS_MASK: u32 = 0x30;
const PTHREAD_PROCESS_SHARED: u32 = 0x10;
const PTHREAD_MTX_OPT_POLICY_MASK: u32 = 0x1c0;
const PTHREAD_MTX_OPT_POLICY_FIRSTFIT: u32 = 0x080;
const PTHREAD_MTX_OPT_MUTEX: u32 = 0x2000;
const PTHREAD_MTX_TID_SWITCHING: u64 = u64::MAX;

/// "Error" bits a failed cvwait returns above its errno (`kern_internal.h`).
pub(crate) const ECVCLEARED: u32 = 0x100;
pub(crate) const ECVPREPOST: u32 = 0x200;

/// `kwq_find_rw_lowest` types.
const PTH_RW_TYPE_READ: u32 = 0x01;
const PTH_RW_TYPE_WRITE: u32 = 0x04;
const PTH_RW_TYPE_MASK: u32 = 0xff;
const PTH_RWSHFT_TYPE_READ: u32 = 0x0100;
const PTH_RWSHFT_TYPE_WRITE: u32 = 0x0400;

/// `kwq_handle_unlock` flags.
const KW_UNLOCK_PREPOST: u32 = 0x01;
const KW_UNLOCK_PREPOST_READLOCK: u32 = 0x08;
const KW_UNLOCK_PREPOST_WRLOCK: u32 = 0x20;

/// `KSYN_CLEANUP_DEADLINE`: an idle rwlock queue keeps its state this long.
const KSYN_CLEANUP_DEADLINE: core::time::Duration = core::time::Duration::from_secs(10);

/// Wait queues a process may have. XNU allocates them from a zone without a
/// per-process limit; here a lookup that needs a new queue in a full table
/// first frees idle rwlock queues early, then fails with ENOMEM. Live
/// waiters hold at most `TASK_THREADMAX` queues; the rest is room for
/// preposted unlocks.
pub(crate) const PSYNCH_MAX_QUEUES: usize = 4 * TASK_THREADMAX as usize;
/// Prepost and broadcast entries (`kw_fakecount`) of all condition
/// variables. A signal that needs one more fails with ENOMEM.
pub(crate) const PSYNCH_MAX_FAKES: usize = 4 * TASK_THREADMAX as usize;

fn is_seqlower(x: u32, y: u32) -> bool {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x < y {
        y - x < PTHRW_MAX_READERS / 2
    } else {
        x - y > PTHRW_MAX_READERS / 2
    }
}

fn is_seqlower_eq(x: u32, y: u32) -> bool {
    x & PTHRW_COUNT_MASK == y & PTHRW_COUNT_MASK || is_seqlower(x, y)
}

fn is_seqhigher(x: u32, y: u32) -> bool {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x > y {
        x - y < PTHRW_MAX_READERS / 2
    } else {
        y - x > PTHRW_MAX_READERS / 2
    }
}

fn is_seqhigher_eq(x: u32, y: u32) -> bool {
    x & PTHRW_COUNT_MASK == y & PTHRW_COUNT_MASK || is_seqhigher(x, y)
}

fn diff_genseq(x: u32, y: u32) -> u32 {
    let (x, y) = (x & PTHRW_COUNT_MASK, y & PTHRW_COUNT_MASK);
    if x >= y {
        x - y
    } else {
        (PTHRW_MAX_READERS - y)
            .wrapping_add(x)
            .wrapping_add(PTHRW_INC)
    }
}

/// Waiters between two sequences.
fn find_diff(upto: u32, lowest: u32) -> u32 {
    if upto == lowest {
        return 0;
    }
    let diff = if is_seqlower(upto, lowest) {
        diff_genseq(lowest, upto)
    } else {
        diff_genseq(upto, lowest)
    };
    diff >> PTHRW_COUNT_SHIFT
}

/// `KSYN_WQTYPE_*`: what a queue serves; a queue serves one kind at a time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Mutex,
    Cvar,
    Rwlock,
}

/// `kwe_state`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KweState {
    /// A blocked thread.
    InWait,
    /// A signal that arrived before its waiter.
    Prepost,
    /// A broadcast that arrived before some of its waiters.
    Broadcast,
}

/// A blocked thread and the value its waker grants it (`kwe_psynchretval`),
/// written and read under the table lock.
struct Blocked<P: ShimPlatform> {
    waiter: Arc<Waiter<P>>,
    granted: AtomicU32,
}

/// `ksyn_waitq_element`: a blocked thread, or a condition variable's
/// prepost or broadcast (a "fake" entry).
struct Kwe<P: ShimPlatform> {
    state: KweState,
    /// The sequence the entry waits at, without the bits.
    lockseq: u32,
    /// Signals a prepost stands for.
    count: u32,
    blocked: Option<Arc<Blocked<P>>>,
}

impl<P: ShimPlatform> Kwe<P> {
    fn thread(&self) -> Option<ThreadId> {
        self.blocked.as_ref().map(|blocked| blocked.waiter.thread)
    }

    /// A blocked thread whose cancellation is pending
    /// (`uthread_is_cancelled`): signals pass it by.
    fn is_cancelled(&self) -> bool {
        self.blocked
            .as_ref()
            .is_some_and(|blocked| blocked.waiter.guest.is_cancelled())
    }
}

/// `ksyn_queue`: entries in sequence order, except that a first-fit mutex
/// queues in arrival order.
struct KsynQueue<P: ShimPlatform> {
    entries: VecDeque<Kwe<P>>,
    firstnum: u32,
    lastnum: u32,
}

impl<P: ShimPlatform> Default for KsynQueue<P> {
    fn default() -> Self {
        Self {
            entries: VecDeque::new(),
            firstnum: 0,
            lastnum: 0,
        }
    }
}

impl<P: ShimPlatform> KsynQueue<P> {
    fn count(&self) -> usize {
        self.entries.len()
    }

    /// `ksyn_queue_count_tolowest`: entries up to and including `upto`.
    fn count_tolowest(&self, upto: u32) -> u32 {
        if self.entries.is_empty() || is_seqhigher(self.firstnum, upto) {
            return 0;
        }
        if upto == self.firstnum {
            return 1;
        }
        let mut count = 0;
        for kwe in &self.entries {
            if is_seqhigher(kwe.lockseq, upto) {
                break;
            }
            count += 1;
            if upto == kwe.lockseq {
                break;
            }
        }
        count
    }

    fn find_seq(&self, seq: u32) -> Option<usize> {
        self.entries.iter().position(|kwe| kwe.lockseq == seq)
    }
}

#[derive(Clone, Copy, Default)]
struct Prepost {
    count: u32,
    lseq: u32,
    sseq: u32,
}

/// Which queue of a wait queue (`kwq_queue_type_t`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum QueueKind {
    Read,
    Write,
}

/// `ksyn_wait_queue`.
struct Kwq<P: ShimPlatform> {
    /// `kw_type`; `None` until a call initializes the queue.
    kind: Option<Kind>,
    /// Calls that found the queue and have not released it (`kw_iocount`),
    /// including blocked threads.
    iocount: u32,
    /// `kw_owner`: the mutex's owner as the kernel knows it.
    owner: Option<ThreadId>,
    /// Fake entries in the write queue (`kw_fakecount`).
    fakecount: u32,
    /// `kw_highseq`.
    highseq: u32,
    lword: u32,
    uword: u32,
    sword: u32,
    /// `kw_lastunlockseq`, which a condition variable keeps as the sequence
    /// the kernel has seen (`kw_cvkernelseq`).
    lastunlockseq: u32,
    lastseqword: u32,
    nextseqword: u32,
    prepost: Prepost,
    /// `KSYN_KWF_INITCLEARED`.
    init_cleared: bool,
    /// `KSYN_KWF_ZEROEDOUT`.
    zeroed_out: bool,
    /// `KSYN_KWF_OVERLAP_GUARD`.
    overlap_guard: bool,
    read: KsynQueue<P>,
    write: KsynQueue<P>,
    /// When the last call released an unused rwlock queue, in
    /// `mach_absolute_time` units (the free list's `kw_stamp`).
    idle_since: Option<u64>,
}

impl<P: ShimPlatform> Default for Kwq<P> {
    fn default() -> Self {
        Self {
            kind: None,
            iocount: 0,
            owner: None,
            fakecount: 0,
            highseq: 0,
            lword: 0,
            uword: 0,
            sword: 0,
            lastunlockseq: 0,
            lastseqword: 0,
            nextseqword: 0,
            prepost: Prepost::default(),
            init_cleared: false,
            zeroed_out: false,
            overlap_guard: false,
            read: KsynQueue::default(),
            write: KsynQueue::default(),
            idle_since: None,
        }
    }
}

/// The fake entries every condition variable holds, against
/// [`PSYNCH_MAX_FAKES`].
struct Fakes(usize);

impl Fakes {
    fn take(&mut self) -> Result<(), Errno> {
        if self.0 >= PSYNCH_MAX_FAKES {
            return Err(Errno::ENOMEM);
        }
        self.0 += 1;
        Ok(())
    }

    fn put(&mut self) {
        self.0 -= 1;
    }
}

impl<P: ShimPlatform> Kwq<P> {
    fn queue(&mut self, which: QueueKind) -> &mut KsynQueue<P> {
        match which {
            QueueKind::Read => &mut self.read,
            QueueKind::Write => &mut self.write,
        }
    }

    fn inqueue(&self) -> usize {
        self.read.count() + self.write.count()
    }

    /// `_kwq_is_used` (`kw_intr` is always clear here).
    fn is_used(&self) -> bool {
        self.inqueue() != 0 || self.prepost.count != 0
    }

    fn clear_preposted_wakeup(&mut self) {
        self.prepost = Prepost {
            count: 0,
            lseq: 0,
            sseq: PTHRW_RWS_INIT,
        };
    }

    fn mark_preposted_wakeup(&mut self, count: u32, lseq: u32, sseq: u32) {
        self.prepost = Prepost { count, lseq, sseq };
    }

    /// `CLEAR_REINIT_BITS`.
    fn clear_reinit_bits(&mut self) {
        if self.kind == Some(Kind::Rwlock) {
            self.nextseqword = PTHRW_RWS_INIT;
            self.overlap_guard = false;
        }
        self.clear_preposted_wakeup();
        self.lastunlockseq = PTHRW_RWL_INIT;
        self.lastseqword = PTHRW_RWS_INIT;
        self.lword = 0;
        self.uword = 0;
        self.sword = PTHRW_RWS_INIT;
    }

    /// `ksyn_wqfind`'s initialization of a new or reused queue.
    fn initialize(&mut self, kind: Kind, mgen: u32, ugen: u32, sgen: u32) {
        self.kind = Some(kind);
        self.clear_reinit_bits();
        self.lword = mgen;
        self.uword = ugen;
        self.sword = sgen;
        self.owner = None;
        self.init_cleared = false;
        self.zeroed_out = false;
        self.overlap_guard = false;
    }

    /// `update_low_high`; only the high sequence is read.
    fn update_high(&mut self, lockseq: u32) {
        if self.inqueue() == 1 || is_seqhigher(lockseq, self.highseq) {
            self.highseq = lockseq;
        }
    }

    /// `find_nexthighseq`.
    fn find_nexthighseq(&self) -> u32 {
        let mut highest = None;
        for queue in [&self.read, &self.write] {
            if queue.count() > 0
                && highest.is_none_or(|highest| is_seqhigher(queue.lastnum, highest))
            {
                highest = Some(queue.lastnum);
            }
        }
        highest.unwrap_or(0)
    }

    /// `ksyn_queue_insert` of an entry at its `lockseq`; first fit appends.
    fn insert(&mut self, which: QueueKind, kwe: Kwe<P>, firstfit: bool) -> Result<(), Errno> {
        let lockseq = kwe.lockseq;
        let queue = self.queue(which);
        if queue.entries.is_empty() {
            queue.entries.push_back(kwe);
            queue.firstnum = lockseq;
            queue.lastnum = lockseq;
        } else if firstfit {
            queue.entries.push_back(kwe);
            if is_seqlower(lockseq, queue.firstnum) {
                queue.firstnum = lockseq;
            }
            if is_seqhigher(lockseq, queue.lastnum) {
                queue.lastnum = lockseq;
            }
        } else if lockseq == queue.firstnum || lockseq == queue.lastnum {
            // A prepost for a canceled waiter's sequence, which the signal
            // passed by, queues beside it.
            let beside_canceled = kwe.state == KweState::Prepost
                && queue
                    .find_seq(lockseq)
                    .is_some_and(|index| queue.entries[index].is_cancelled());
            if !beside_canceled {
                return Err(Errno::EBUSY);
            }
            queue.entries.push_back(kwe);
        } else if is_seqlower(queue.lastnum, lockseq) {
            queue.entries.push_back(kwe);
            queue.lastnum = lockseq;
        } else if is_seqlower(lockseq, queue.firstnum) {
            queue.entries.push_front(kwe);
            queue.firstnum = lockseq;
        } else {
            let index = queue
                .entries
                .iter()
                .position(|queued| is_seqhigher(queued.lockseq, lockseq))
                .ok_or(Errno::ESRCH)?;
            queue.entries.insert(index, kwe);
        }
        self.update_high(lockseq);
        Ok(())
    }

    /// `ksyn_queue_remove_item`.
    fn remove(&mut self, which: QueueKind, index: usize) -> Kwe<P> {
        let queue = self.queue(which);
        let kwe = queue.entries.remove(index).expect("a queued entry");
        if let (Some(first), Some(last)) = (queue.entries.front(), queue.entries.back()) {
            queue.firstnum = first.lockseq;
            queue.lastnum = last.lockseq;
        } else {
            queue.firstnum = 0;
            queue.lastnum = 0;
        }
        if self.inqueue() > 0 {
            if self.highseq == kwe.lockseq {
                self.highseq = self.find_nexthighseq();
            }
        } else {
            self.highseq = 0;
        }
        kwe
    }

    /// Remove a fake entry and return it to the budget.
    fn discard_fake(&mut self, index: usize, fakes: &mut Fakes) {
        self.remove(QueueKind::Write, index);
        self.fakecount -= 1;
        fakes.put();
    }

    /// `ksyn_prepost`: queue a fake entry.
    fn prepost_fake(
        &mut self,
        state: KweState,
        lockseq: u32,
        fakes: &mut Fakes,
    ) -> Result<(), Errno> {
        fakes.take()?;
        let kwe = Kwe {
            state,
            lockseq,
            count: 1,
            blocked: None,
        };
        if self.insert(QueueKind::Write, kwe, false).is_ok() {
            self.fakecount += 1;
        } else {
            fakes.put();
        }
        Ok(())
    }

    /// `ksyn_signal`: grant `value` to the blocked thread at `index` and wake
    /// it. Returns the thread. Mutex and rwlock queues hold only blocked
    /// threads, and condition variables signal only those.
    fn signal(&mut self, which: QueueKind, index: usize, value: u32) -> ThreadId {
        let kwe = self.remove(which, index);
        let blocked = kwe.blocked.expect("only a blocked thread is signaled");
        blocked.granted.store(value, Ordering::Relaxed);
        blocked.waiter.wake();
        blocked.waiter.thread
    }

    /// Withdraw a blocked thread whose wait ended; `false` if a waker took
    /// it first.
    fn withdraw(&mut self, which: QueueKind, blocked: &Arc<Blocked<P>>) -> bool {
        let Some(index) = self.queue(which).entries.iter().position(|kwe| {
            kwe.blocked
                .as_ref()
                .is_some_and(|queued| Arc::ptr_eq(queued, blocked))
        }) else {
            return false;
        };
        self.remove(which, index);
        true
    }

    /// `_ksyn_check_init`.
    fn check_init(&mut self, lgenval: u32) -> bool {
        let init = lgenval & PTHRW_RWL_INIT != 0;
        if init && !self.init_cleared {
            self.clear_reinit_bits();
            self.init_cleared = true;
        }
        init
    }

    /// `UPDATE_CVKWQ`.
    fn update_cv(&mut self, mgen: u32, ugen: u32, rw_wc: u32) {
        let sinit = rw_wc & PTH_RWS_CV_CBIT != 0;
        if self.zeroed_out {
            self.lword = mgen;
            self.uword = ugen;
            self.sword = rw_wc;
            self.zeroed_out = false;
        } else {
            if is_seqhigher(mgen, self.lword) {
                self.lword = mgen;
            }
            if is_seqhigher(ugen, self.uword) {
                self.uword = ugen;
            }
            if sinit && is_seqhigher(rw_wc, self.sword) {
                self.sword = rw_wc;
            }
        }
        if sinit && is_seqlower(self.lastunlockseq, rw_wc) {
            self.lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
        }
    }
}

/// `ksyn_wq_hash_lookup`'s key: the address in this process, or for a
/// process-shared object its memory object and offset. As for shared
/// ulocks, the address and the generation of the mapping there stand in for
/// the object; a mapping change retires the old generation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PsynchKey {
    Private(usize),
    Shared { address: usize, generation: u64 },
}

impl PsynchKey {
    fn address(self) -> usize {
        match self {
            Self::Private(address) | Self::Shared { address, .. } => address,
        }
    }
}

/// Every psynch wait queue of the process.
pub(crate) struct PsynchTable<P: ShimPlatform> {
    queues: BTreeMap<PsynchKey, Kwq<P>>,
    /// The current mapping generation at addresses whose mapping changed
    /// while a call held a shared queue there; absent means 0.
    generations: BTreeMap<usize, u64>,
    next_generation: u64,
    fakes: Fakes,
}

impl<P: ShimPlatform> Default for PsynchTable<P> {
    fn default() -> Self {
        Self {
            queues: BTreeMap::new(),
            generations: BTreeMap::new(),
            next_generation: 1,
            fakes: Fakes(0),
        }
    }
}

/// How a blocked thread's wait ended.
enum Blocking {
    /// A waker granted the value.
    Granted(u32),
    /// The wait ended without a grant (`ETIMEDOUT`, `EINTR`).
    Ended(Errno),
    /// The thread could not queue at its sequence (`ksyn_wait`'s insert).
    Refused(Errno),
}

impl<P: ShimPlatform> PsynchTable<P> {
    /// Threads blocked on the private queue at `address`.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn waiters(&self, address: usize) -> usize {
        self.queues
            .get(&PsynchKey::Private(address))
            .map_or(0, Kwq::inqueue)
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn queue_count(&self) -> usize {
        self.queues.len()
    }

    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn fake_count(&self) -> usize {
        self.fakes.0
    }

    /// Wake every blocked thread with a zero grant; returns how many.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn release_all_waiters(&mut self) -> usize {
        let mut released = 0;
        for kwq in self.queues.values_mut() {
            for which in [QueueKind::Read, QueueKind::Write] {
                while let Some(index) = kwq
                    .queue(which)
                    .entries
                    .iter()
                    .position(|kwe| kwe.state == KweState::InWait)
                {
                    kwq.signal(which, index, 0);
                    released += 1;
                }
            }
        }
        released
    }

    /// Move every idle queue's release `ticks` into the past.
    #[cfg(all(test, target_os = "macos"))]
    pub(crate) fn age_idle_queues(&mut self, ticks: u64) {
        for kwq in self.queues.values_mut() {
            if let Some(since) = kwq.idle_since.as_mut() {
                *since = since.wrapping_sub(ticks);
            }
        }
    }

    fn shared_key(&self, address: usize) -> PsynchKey {
        PsynchKey::Shared {
            address,
            generation: self.generations.get(&address).copied().unwrap_or(0),
        }
    }

    /// `ksyn_wqfind`: find or create `key`'s queue for `kind` and take a
    /// reference. An idle rwlock queue whose state expired is freed first,
    /// as XNU's cleanup thread would have.
    #[expect(clippy::too_many_arguments)]
    fn find(
        &mut self,
        key: PsynchKey,
        kind: Kind,
        mgen: u32,
        ugen: u32,
        sgen: u32,
        now: u64,
        expiry: u64,
    ) -> Result<(), Errno> {
        if self
            .queues
            .get(&key)
            .and_then(|kwq| kwq.idle_since)
            .is_some_and(|since| now.wrapping_sub(since) >= expiry)
        {
            self.queues.remove(&key);
        }
        if !self.queues.contains_key(&key) && self.queues.len() >= PSYNCH_MAX_QUEUES {
            let idle: Vec<PsynchKey> = self
                .queues
                .iter()
                .filter(|(_, kwq)| kwq.idle_since.is_some())
                .map(|(key, _)| *key)
                .collect();
            for key in idle {
                self.discard(key);
            }
            if self.queues.len() >= PSYNCH_MAX_QUEUES {
                return Err(Errno::ENOMEM);
            }
        }
        let kwq = self.queues.entry(key).or_default();
        kwq.idle_since = None;
        if kwq.kind != Some(kind) {
            if kwq.is_used() || kwq.iocount != 0 {
                return Err(Errno::EINVAL);
            }
            kwq.kind = None;
        }
        if kwq.kind.is_none() {
            kwq.initialize(kind, mgen, ugen, sgen);
        }
        kwq.iocount += 1;
        Ok(())
    }

    fn kwq(&mut self, key: PsynchKey) -> &mut Kwq<P> {
        self.queues.get_mut(&key).expect("a call holds the queue")
    }

    /// `ksyn_wqrelease`: drop a reference. An unused queue is freed, or for
    /// an rwlock (`idle_at`) kept idle until its state expires. A shared
    /// queue whose mapping changed is freed even with preposts, since no
    /// call can reach it again.
    fn release(&mut self, key: PsynchKey, idle_at: Option<u64>) {
        let kwq = self.kwq(key);
        kwq.iocount -= 1;
        if kwq.iocount != 0 {
            return;
        }
        let retired =
            matches!(key, PsynchKey::Shared { .. }) && self.shared_key(key.address()) != key;
        let kwq = self.kwq(key);
        if retired || !kwq.is_used() {
            match idle_at {
                Some(now) if !retired => kwq.idle_since = Some(now),
                _ => self.discard(key),
            }
        }
    }

    fn discard(&mut self, key: PsynchKey) {
        let kwq = self.queues.remove(&key).expect("a queue to discard");
        self.fakes.0 -= kwq.fakecount as usize;
        if let PsynchKey::Shared { address, .. } = key
            && self
                .queues
                .range(
                    PsynchKey::Shared {
                        address,
                        generation: 0,
                    }..=PsynchKey::Shared {
                        address,
                        generation: u64::MAX,
                    },
                )
                .next()
                .is_none()
        {
            // No queue remains at the address, so generation 0 can name the
            // next object there.
            self.generations.remove(&address);
        }
    }

    /// The mappings in `range` were replaced or removed: free their shared
    /// queues no call holds, and start a new generation where a call still
    /// holds one, so no later call reaches it. Callers hold the table lock
    /// from before the mapping change until this returns.
    pub(crate) fn retire_objects(&mut self, range: Range<usize>) {
        let shared: Vec<PsynchKey> = self
            .queues
            .range(
                PsynchKey::Shared {
                    address: range.start,
                    generation: 0,
                }..,
            )
            .map(|(key, _)| *key)
            .take_while(|key| key.address() < range.end)
            .collect();
        let mut held = Vec::new();
        for key in shared {
            if self.queues[&key].iocount == 0 {
                self.discard(key);
            } else {
                held.push(key.address());
            }
        }
        held.dedup();
        for address in held {
            let generation = self.next_generation;
            self.next_generation += 1;
            self.generations.insert(address, generation);
        }
    }

    /// `ksyn_cvupdate_fixup`.
    fn cv_fixup(&mut self, key: PsynchKey, updatebits: &mut u32) {
        let Self { queues, fakes, .. } = self;
        let kwq = queues.get_mut(&key).expect("a call holds the queue");
        if kwq.lword & PTHRW_COUNT_MASK == kwq.sword & PTHRW_COUNT_MASK {
            if kwq.inqueue() != 0 {
                let lword = kwq.lword;
                free_items(kwq, fakes, lword, false);
            }
            kwq.lword = 0;
            kwq.uword = 0;
            kwq.sword = 0;
            kwq.zeroed_out = true;
            *updatebits |= PTH_RWS_CV_CBIT;
        } else if kwq.inqueue() != 0 && kwq.fakecount as usize == kwq.inqueue() {
            *updatebits |= PTH_RWS_CV_PBIT;
        }
    }
}

/// `ksyn_queue_free_items` of the write queue: wake blocked threads with a
/// spurious return and drop fake entries, up to `upto` or all of them.
fn free_items<P: ShimPlatform>(kwq: &mut Kwq<P>, fakes: &mut Fakes, upto: u32, all: bool) {
    let upto = upto & PTHRW_COUNT_MASK;
    while let Some(kwe) = kwq.write.entries.front() {
        if !all && is_seqhigher(kwe.lockseq, upto) {
            break;
        }
        if kwe.state == KweState::InWait {
            kwq.signal(
                QueueKind::Write,
                0,
                PTHRW_INC | PTH_RWS_CV_MBIT | PTH_RWL_MTX_WAIT,
            );
        } else {
            kwq.discard_fake(0, fakes);
        }
    }
}

/// `ksyn_handle_cvbroad`: wake every blocked thread up to `upto`, fold the
/// fake entries there into one broadcast entry unless the condition variable
/// is balanced, and add the woken threads to `updatebits`.
fn handle_cvbroad<P: ShimPlatform>(
    kwq: &mut Kwq<P>,
    fakes: &mut Fakes,
    upto: u32,
    updatebits: &mut u32,
) -> Result<(), Errno> {
    let mut woken = 0u32;
    // Every entry up to `upto` leaves the queue except canceled waiters.
    let mut index = 0;
    while let Some(kwe) = kwq.write.entries.get(index) {
        if is_seqhigher(kwe.lockseq, upto) {
            break;
        }
        if kwe.state != KweState::InWait {
            kwq.discard_fake(index, fakes);
        } else if kwe.is_cancelled() {
            index += 1;
        } else {
            kwq.signal(QueueKind::Write, index, PTH_RWL_MTX_WAIT);
            woken = woken.wrapping_add(PTHRW_INC);
        }
    }
    let result = if diff_genseq(kwq.lword, kwq.sword) != 0 {
        kwq.prepost_fake(KweState::Broadcast, upto, fakes)
    } else {
        Ok(())
    };
    *updatebits |= woken;
    result
}

/// `ksyn_queue_find_signalseq`: the entry a signal up to `uptoseq` reaches,
/// preferring a blocked thread at or above `signalseq`.
fn find_signalseq<P: ShimPlatform>(
    queue: &KsynQueue<P>,
    uptoseq: u32,
    signalseq: u32,
) -> Option<usize> {
    let mut result = None;
    for (index, kwe) in queue.entries.iter().enumerate() {
        match kwe.state {
            KweState::Prepost | KweState::Broadcast => {
                if kwe.state == KweState::Prepost && is_seqhigher(kwe.lockseq, uptoseq) {
                    return result;
                }
                if !is_seqlower(kwe.lockseq, uptoseq) {
                    return Some(index);
                }
            }
            KweState::InWait => {
                if is_seqhigher(kwe.lockseq, uptoseq) {
                    return result;
                }
                if kwe.is_cancelled() {
                    continue;
                }
                if is_seqhigher_eq(kwe.lockseq, signalseq) {
                    return Some(index);
                }
                result.get_or_insert(index);
            }
        }
    }
    result
}

/// `ksyn_queue_find_cvpreposeq`: the entry at `cgen` or a fake one above.
fn find_cvpreposeq<P: ShimPlatform>(queue: &KsynQueue<P>, cgen: u32) -> Option<usize> {
    let lgen = cgen & PTHRW_COUNT_MASK;
    let (index, kwe) = queue
        .entries
        .iter()
        .enumerate()
        .find(|(_, kwe)| is_seqhigher_eq(kwe.lockseq, cgen))?;
    (kwe.state != KweState::InWait || kwe.lockseq == lgen).then_some(index)
}

/// `kwq_find_rw_lowest`: the lowest reader and writer sequences, counting a
/// preposting locker at `premgen`, and which kind holds the lowest.
fn find_rw_lowest<P: ShimPlatform>(kwq: &Kwq<P>, flags: u32, premgen: u32) -> (u32, u32, u32) {
    let mut kind = 0;
    let mut candidates: [(u32, u32); 2] = [(0, 0); 2];
    let mut count = 0;
    let mut lowest = [0u32; 2];
    for (index, (queue, prepost, shifted, plain)) in [
        (
            &kwq.read,
            KW_UNLOCK_PREPOST_READLOCK,
            PTH_RWSHFT_TYPE_READ,
            PTH_RW_TYPE_READ,
        ),
        (
            &kwq.write,
            KW_UNLOCK_PREPOST_WRLOCK,
            PTH_RWSHFT_TYPE_WRITE,
            PTH_RW_TYPE_WRITE,
        ),
    ]
    .into_iter()
    .enumerate()
    {
        if queue.count() == 0 && flags & prepost == 0 {
            continue;
        }
        kind |= shifted;
        let first = if queue.count() == 0
            || (flags & prepost != 0 && is_seqlower(premgen, queue.firstnum))
        {
            premgen
        } else {
            queue.firstnum
        };
        lowest[index] = first;
        candidates[count] = (first, plain);
        count += 1;
    }
    let (mut low, mut lowtype) = candidates[0];
    for &(number, plain) in &candidates[1..count.max(1)] {
        if is_seqlower(number, low) {
            low = number;
            lowtype = plain;
        }
    }
    (kind | lowtype, lowest[0], lowest[1])
}

/// The value a call returns, or its error. With psynch's `uint32_t`
/// results the value is zero-extended into x0.
fn syscall_value(result: Result<u32, Errno>) -> Result<usize, Errno> {
    result.map(|value| value as usize)
}

impl<P: ShimPlatform> Task<P> {
    /// `ksyn_wqfind`'s key: a process-shared object (`ksyn_findobj`, EINVAL
    /// if nothing is mapped there) or this process's address.
    fn psynch_key(
        &self,
        table: &PsynchTable<P>,
        address: usize,
        flags: u32,
    ) -> Result<PsynchKey, Errno> {
        if flags & PTHREAD_PSHARED_FLAGS_MASK != PTHREAD_PROCESS_SHARED {
            return Ok(PsynchKey::Private(address));
        }
        if self
            .global
            .mm
            .overlapping(address..address.saturating_add(1))
            .is_empty()
        {
            return Err(Errno::EINVAL);
        }
        Ok(table.shared_key(address))
    }

    /// `KSYN_CLEANUP_DEADLINE` in `mach_absolute_time` units.
    pub(crate) fn psynch_cleanup_ticks(&self) -> u64 {
        let timebase = self.global.platform.mach_timebase_info();
        let ticks = KSYN_CLEANUP_DEADLINE.as_nanos() * u128::from(timebase.denom)
            / u128::from(timebase.numer.max(1));
        u64::try_from(ticks).unwrap_or(u64::MAX)
    }

    /// Look up `address`'s queue for `kind` under the table lock and take a
    /// reference (`ksyn_wqfind`).
    #[expect(clippy::too_many_arguments)]
    fn psynch_find(
        &self,
        table: &mut PsynchTable<P>,
        address: usize,
        flags: u32,
        kind: Kind,
        mgen: u32,
        ugen: u32,
        sgen: u32,
    ) -> Result<PsynchKey, Errno> {
        let key = self.psynch_key(table, address, flags)?;
        let now = self.global.platform.mach_absolute_time();
        table.find(
            key,
            kind,
            mgen,
            ugen,
            sgen,
            now,
            self.psynch_cleanup_ticks(),
        )?;
        Ok(key)
    }

    /// `ksyn_wait`: queue the calling thread at `lockseq` and block until a
    /// waker grants it a value, `timeout` passes, the process exits, or the
    /// thread is aborted (`THREAD_ABORTSAFE`). The queue's reference keeps it
    /// in the table while the lock is released.
    fn psynch_block<'a>(
        &'a self,
        mut table: MutexGuard<'a, P, PsynchTable<P>>,
        key: PsynchKey,
        which: QueueKind,
        lockseq: u32,
        firstfit: bool,
        timeout: Option<core::time::Duration>,
    ) -> (MutexGuard<'a, P, PsynchTable<P>>, Blocking) {
        let blocked = Arc::new(Blocked {
            waiter: self.new_waiter(),
            granted: AtomicU32::new(0),
        });
        let kwe = Kwe {
            state: KweState::InWait,
            lockseq: lockseq & PTHRW_COUNT_MASK,
            count: 1,
            blocked: Some(Arc::clone(&blocked)),
        };
        if let Err(error) = table.kwq(key).insert(which, kwe, firstfit) {
            return (table, Blocking::Refused(error));
        }
        drop(table);
        let result = self.wait_for_wakeup(&blocked.waiter, timeout);
        #[cfg(all(test, target_os = "macos"))]
        self.global
            .mapping_hook
            .reach(crate::syscalls::mm::hook::Point::PsynchWaited);
        let mut table = self.global.psynch.lock();
        let outcome = match result {
            WaitResult::TimedOut if table.kwq(key).withdraw(which, &blocked) => {
                Blocking::Ended(Errno::ETIMEDOUT)
            }
            WaitResult::Interrupted if table.kwq(key).withdraw(which, &blocked) => {
                Blocking::Ended(Errno::EINTR)
            }
            _ => Blocking::Granted(blocked.granted.load(Ordering::Relaxed)),
        };
        (table, outcome)
    }

    /// Log the first time a call fails because the table is full.
    fn psynch_result(&self, result: Result<usize, Errno>) -> Result<usize, Errno> {
        if result == Err(Errno::ENOMEM) {
            self.log_unsupported_once(
                "psynch table limit",
                format_args!(
                    "more than {PSYNCH_MAX_QUEUES} wait queues or {PSYNCH_MAX_FAKES} condition \
                     variable preposts"
                ),
            );
        }
        result
    }

    /// The live thread with ID `tid` (`task_findtid`).
    fn thread_with_id(&self, tid: u64) -> Option<ThreadId> {
        self.guest_thread(tid).map(|thread| thread.id)
    }

    /// `psynch_mutexwait` (BSD 301) and `psynch_mutexdrop` (BSD 302).
    pub(crate) fn sys_psynch_mutex(
        &self,
        drop: bool,
        mutex: usize,
        mgen: u32,
        ugen: u32,
        tid: u64,
        flags: u32,
    ) -> Result<usize, Errno> {
        let result = if drop {
            let mut table = self.global.psynch.lock();
            self.psynch_mutexdrop(&mut table, mutex, mgen, ugen, flags)
                .map(|()| 0)
        } else {
            syscall_value(self.psynch_mutexwait(mutex, mgen, ugen, tid, flags))
        };
        self.psynch_result(result)
    }

    /// `_psynch_mutexwait`.
    fn psynch_mutexwait(
        &self,
        mutex: usize,
        mgen: u32,
        ugen: u32,
        tid: u64,
        flags: u32,
    ) -> Result<u32, Errno> {
        let firstfit = flags & PTHREAD_MTX_OPT_POLICY_MASK == PTHREAD_MTX_OPT_POLICY_FIRSTFIT;
        let lseq = mgen & PTHRW_COUNT_MASK;
        // The owner hint, resolved before the table lock like XNU's
        // task_findtid after it drops the queue lock.
        let hinted = (tid != 0 && tid != PTHREAD_MTX_TID_SWITCHING)
            .then(|| self.thread_with_id(tid))
            .flatten();
        let mut table = self.global.psynch.lock();
        let key = self.psynch_find(&mut table, mutex, flags, Kind::Mutex, mgen, ugen, 0)?;
        let self_id = self.thread.guest.id;
        let kwq = table.kwq(key);
        if kwq.prepost.count != 0 && (firstfit || lseq == kwq.prepost.lseq) {
            kwq.prepost.count -= 1;
            if !firstfit {
                if kwq.prepost.count > 0 {
                    // "more than one prepost"
                    kwq.prepost.lseq = kwq.prepost.lseq.wrapping_add(PTHRW_INC);
                    table.release(key, None);
                    return Err(Errno::EINVAL);
                }
                kwq.clear_preposted_wakeup();
            }
            let updatebits = if kwq.inqueue() == 0 {
                lseq
            } else {
                kwq.highseq & PTHRW_COUNT_MASK
            } | PTH_RWL_KBIT
                | PTH_RWL_EBIT;
            kwq.owner = Some(self_id);
            table.release(key, None);
            return Ok(updatebits & !PTH_RWL_MTX_WAIT);
        }
        let owner_tid = kwq.owner.unwrap_or(0);
        let stale = kwq.lastunlockseq != PTHRW_RWL_INIT && is_seqlower(ugen, kwq.lastunlockseq);
        if tid != owner_tid && tid != 0 && !stale && tid != PTHREAD_MTX_TID_SWITCHING {
            // A hint for a specific thread the kernel has no reason to doubt.
            if let Some(thread) = hinted {
                kwq.owner = Some(thread);
            }
        }
        let (mut table, outcome) =
            self.psynch_block(table, key, QueueKind::Write, mgen, firstfit, None);
        let result = match outcome {
            Blocking::Granted(value) => Ok(value & !PTH_RWL_MTX_WAIT),
            Blocking::Ended(error) | Blocking::Refused(error) => Err(error),
        };
        table.release(key, None);
        result
    }

    /// `_psynch_mutexdrop` and `_psynch_mutexdrop_internal`: the unlock of a
    /// contended mutex grants it to a waiter or preposts it.
    fn psynch_mutexdrop(
        &self,
        table: &mut PsynchTable<P>,
        mutex: usize,
        mgen: u32,
        ugen: u32,
        flags: u32,
    ) -> Result<(), Errno> {
        let key = self.psynch_find(table, mutex, flags, Kind::Mutex, mgen, ugen, 0)?;
        let firstfit = flags & PTHREAD_MTX_OPT_POLICY_MASK == PTHREAD_MTX_OPT_POLICY_FIRSTFIT;
        let nextgen = ugen.wrapping_add(PTHRW_INC);
        let kwq = table.kwq(key);
        kwq.lastunlockseq = ugen & PTHRW_COUNT_MASK;
        let updatebits = (kwq.highseq & PTHRW_COUNT_MASK) | PTH_RWL_EBIT | PTH_RWL_KBIT;
        let mut prepost = false;
        if firstfit {
            if kwq.inqueue() == 0 {
                let count = kwq.prepost.count + 1;
                kwq.mark_preposted_wakeup(count, mgen & PTHRW_COUNT_MASK, 0);
                kwq.owner = None;
            } else {
                kwq.owner = Some(kwq.signal(QueueKind::Write, 0, updatebits));
            }
        } else if kwq.inqueue() == 0 {
            prepost = true;
        } else {
            let low_writer = kwq.write.firstnum & PTHRW_COUNT_MASK;
            // The grant could be a condition variable's, so the mutex-wait
            // bit stays set for a thread that left its wait.
            if low_writer == nextgen {
                kwq.owner = Some(kwq.signal(QueueKind::Write, 0, updatebits | PTH_RWL_MTX_WAIT));
            } else if is_seqhigher(low_writer, nextgen) {
                prepost = true;
            } else if let Some(index) = kwq.write.find_seq(nextgen) {
                kwq.owner =
                    Some(kwq.signal(QueueKind::Write, index, updatebits | PTH_RWL_MTX_WAIT));
            } else {
                prepost = true;
            }
        }
        if prepost {
            // A second prepost is a userspace bug XNU only reports.
            if kwq.prepost.count == 0 {
                kwq.mark_preposted_wakeup(1, nextgen & PTHRW_COUNT_MASK, 0);
            }
            kwq.owner = None;
        }
        table.release(key, None);
        Ok(())
    }

    /// `psynch_cvsignal` (BSD 304) and `psynch_cvbroad` (BSD 303). A
    /// broadcast's `cvudgen` holds U above the number of waiters it wakes.
    pub(crate) fn sys_psynch_cvsignal(
        &self,
        cv: usize,
        cvlsgen: u64,
        cvudgen: u64,
        thread_port: Option<u32>,
        flags: u32,
    ) -> Result<usize, Errno> {
        let csgen: u32 = (cvlsgen >> 32).trunc();
        let cgen: u32 = cvlsgen.trunc();
        let (cugen, broadcast, port) = match thread_port {
            None => {
                if TruncateExt::<u32>::trunc(cvudgen) >> PTHRW_COUNT_SHIFT > TASK_THREADMAX {
                    // "difference greater than maximum possible thread count"
                    return Err(Errno::EBUSY);
                }
                ((cvudgen >> 32).trunc(), true, 0)
            }
            Some(port) => (cvudgen.trunc(), false, port),
        };
        let result = self.psynch_cvsignal(cv, cgen, cugen, csgen, flags, broadcast, port);
        self.psynch_result(syscall_value(result))
    }

    /// `__psynch_cvsignal`.
    #[expect(clippy::too_many_arguments)]
    fn psynch_cvsignal(
        &self,
        cv: usize,
        cgen: u32,
        cugen: u32,
        csgen: u32,
        flags: u32,
        mut broadcast: bool,
        thread_port: u32,
    ) -> Result<u32, Errno> {
        let uptoseq = cgen & PTHRW_COUNT_MASK;
        let fromseq = (cugen & PTHRW_COUNT_MASK).wrapping_add(PTHRW_INC);
        if (thread_port == 0 && is_seqhigher(fromseq, uptoseq)) || is_seqhigher(csgen, uptoseq) {
            // "invalid L, U and S values"
            return Err(Errno::EINVAL);
        }
        let thread = if thread_port == 0 {
            None
        } else {
            Some(
                self.global
                    .ipc
                    .lock()
                    .thread_for_name(thread_port)
                    .ok_or(Errno::ESRCH)?,
            )
        };
        let mut table = self.global.psynch.lock();
        let key = self.psynch_find(&mut table, cv, flags, Kind::Cvar, cgen, cugen, csgen)?;
        let PsynchTable { queues, fakes, .. } = &mut *table;
        let kwq = queues.get_mut(&key).expect("a call holds the queue");
        kwq.update_cv(cgen, cugen, csgen);
        let mut updatebits = 0;
        let mut result = Ok(());
        if !broadcast && diff_genseq(kwq.lword, kwq.sword) != 0 {
            match thread {
                Some(thread) => {
                    cvsignal_thread(
                        kwq,
                        thread,
                        uptoseq,
                        fromseq,
                        &mut updatebits,
                        &mut broadcast,
                    );
                }
                None => {
                    result = cvsignal_any(
                        kwq,
                        fakes,
                        uptoseq,
                        fromseq,
                        &mut updatebits,
                        &mut broadcast,
                    );
                }
            }
        }
        if broadcast {
            result = handle_cvbroad(kwq, fakes, uptoseq, &mut updatebits);
        }
        kwq.sword = kwq.sword.wrapping_add(updatebits & PTHRW_COUNT_MASK);
        table.cv_fixup(key, &mut updatebits);
        table.release(key, None);
        result.map(|()| updatebits)
    }

    /// `psynch_cvwait` (BSD 305): release `mutex` (when its unlock must
    /// notify the kernel) and wait on the condition variable, for at most
    /// `seconds` and `nanoseconds` if either is nonzero. A failure returns
    /// [`ECVCLEARED`] and [`ECVPREPOST`] above the errno; the second value is
    /// those bits.
    #[expect(clippy::too_many_arguments)]
    pub(crate) fn sys_psynch_cvwait(
        &self,
        cv: usize,
        cvlsgen: u64,
        cvugen: u32,
        mutex: usize,
        mugen: u64,
        flags: u32,
        seconds: i64,
        nanoseconds: u32,
    ) -> Result<usize, (Errno, u32)> {
        let result = self.psynch_cvwait(
            cv,
            cvlsgen,
            cvugen,
            mutex,
            mugen,
            flags,
            seconds,
            nanoseconds,
        );
        if let Err((Errno::ENOMEM, _)) = result {
            let _ = self.psynch_result(Err(Errno::ENOMEM));
        }
        result.map(|value| value as usize)
    }

    /// `_psynch_cvwait` and `psynch_cvcontinue`.
    #[expect(clippy::too_many_arguments)]
    fn psynch_cvwait(
        &self,
        cv: usize,
        cvlsgen: u64,
        cvugen: u32,
        mutex: usize,
        mugen: u64,
        flags: u32,
        seconds: i64,
        nanoseconds: u32,
    ) -> Result<u32, (Errno, u32)> {
        // "for conformance reasons": a pending cancellation aborts the wait.
        let _ = self.testcancel(TestCancel::BeforeWait);
        let csgen: u32 = (cvlsgen >> 32).trunc();
        let cgen: u32 = cvlsgen.trunc();
        let ugen: u32 = (mugen >> 32).trunc();
        let mgen: u32 = mugen.trunc();
        let lockseq = cgen & PTHRW_COUNT_MASK;
        // The U word may be out of range when a condition variable is used
        // only for timeouts; S must not be.
        if is_seqhigher_eq(csgen, lockseq) {
            return Err((Errno::EINVAL, 0));
        }
        let mut table = self.global.psynch.lock();
        let key = self
            .psynch_find(&mut table, cv, flags, Kind::Cvar, cgen, cvugen, csgen)
            .map_err(|error| (error, 0))?;
        if mutex != 0
            && let Err(error) = self.psynch_mutexdrop(&mut table, mutex, mgen, ugen, flags)
        {
            table.release(key, None);
            return Err((error, 0));
        }
        let PsynchTable { queues, fakes, .. } = &mut *table;
        let kwq = queues.get_mut(&key).expect("a call holds the queue");
        kwq.update_cv(cgen, cvugen, csgen);
        if let Some(index) = find_cvpreposeq(&kwq.write, lockseq) {
            let mut updatebits = 0;
            let (state, found) = {
                let kwe = &kwq.write.entries[index];
                (kwe.state, kwe.lockseq)
            };
            let result = match state {
                KweState::Prepost if found == lockseq => {
                    let kwe = &mut kwq.write.entries[index];
                    kwe.count -= 1;
                    if kwe.count == 0 {
                        kwq.discard_fake(index, fakes);
                    }
                    Ok(())
                }
                // Consuming a later signal could leave its waiter without
                // one, so it becomes a broadcast. That removes at least the
                // prepost before it adds a broadcast entry.
                KweState::Prepost => handle_cvbroad(kwq, fakes, found, &mut updatebits),
                KweState::Broadcast => Ok(()),
                // "thread entry with same sequence already present"
                KweState::InWait => Err(Errno::EBUSY),
            };
            if result.is_ok() {
                updatebits |= PTHRW_INC;
                kwq.sword = kwq.sword.wrapping_add(PTHRW_INC);
                table.cv_fixup(key, &mut updatebits);
            }
            table.release(key, None);
            return result.map(|()| updatebits).map_err(|error| (error, 0));
        }
        let timeout = (seconds != 0 || nanoseconds & 0x3fff_ffff != 0).then(|| {
            // XNU computes the interval in 64 unsigned bits.
            let nanoseconds = seconds
                .cast_unsigned()
                .wrapping_mul(1_000_000_000)
                .wrapping_add(u64::from(nanoseconds & 0x3fff_ffff));
            core::time::Duration::from_nanos(nanoseconds)
        });
        let (mut table, outcome) =
            self.psynch_block(table, key, QueueKind::Write, cgen, false, timeout);
        let result = match outcome {
            Blocking::Granted(value) => Ok(if value & PTH_RWS_CV_MBIT != 0 {
                PTHRW_INC | PTH_RWS_CV_CBIT
            } else {
                0
            }),
            Blocking::Refused(error) => Err((error, 0)),
            Blocking::Ended(error) => {
                let PsynchTable { queues, fakes, .. } = &mut *table;
                let kwq = queues.get_mut(&key).expect("a call holds the queue");
                kwq.sword = kwq.sword.wrapping_add(PTHRW_INC);
                let bits = if kwq.lword & PTHRW_COUNT_MASK == kwq.sword & PTHRW_COUNT_MASK {
                    if kwq.inqueue() != 0 {
                        let lword = kwq.lword;
                        free_items(kwq, fakes, lword, true);
                    }
                    kwq.lword = 0;
                    kwq.uword = 0;
                    kwq.sword = 0;
                    kwq.zeroed_out = true;
                    ECVCLEARED
                } else if kwq.inqueue() != 0 && kwq.fakecount as usize == kwq.inqueue() {
                    ECVPREPOST
                } else {
                    0
                };
                Err((error, bits))
            }
        };
        table.release(key, None);
        result
    }

    /// `psynch_cvclrprepost` (BSD 312): clear a mutex's first-fit prepost up
    /// to `cvgen`, or a condition variable's fake entries up to `preposeq`.
    pub(crate) fn sys_psynch_cvclrprepost(
        &self,
        cv: usize,
        cvgen: u32,
        cvugen: u32,
        cvsgen: u32,
        preposeq: u32,
        flags: u32,
    ) -> Result<usize, Errno> {
        let mutex = flags & PTHREAD_MTX_OPT_MUTEX != 0;
        let mut table = self.global.psynch.lock();
        let (kind, sgen) = if mutex {
            (Kind::Mutex, 0)
        } else {
            (Kind::Cvar, cvsgen)
        };
        let key = self.psynch_find(&mut table, cv, flags, kind, cvgen, cvugen, sgen)?;
        let PsynchTable { queues, fakes, .. } = &mut *table;
        let kwq = queues.get_mut(&key).expect("a call holds the queue");
        if mutex {
            let firstfit = flags & PTHREAD_MTX_OPT_POLICY_MASK == PTHREAD_MTX_OPT_POLICY_FIRSTFIT;
            if firstfit && kwq.prepost.count != 0 && is_seqlower_eq(kwq.prepost.lseq, cvgen) {
                kwq.clear_preposted_wakeup();
            }
        } else {
            free_items(kwq, fakes, preposeq, false);
        }
        table.release(key, None);
        Ok(0)
    }

    /// The `psynch_rw_*` calls (BSD 297-300, 306-309). XNU's pthread kext
    /// answers `longrdlock` and `yieldwrlock` with ESRCH, and its BSD shims
    /// answer `upgrade` and `downgrade` with success and `unlock2` with
    /// ENOTSUP, all without looking at the lock.
    pub(crate) fn sys_psynch_rw(
        &self,
        operation: PsynchRwOperation,
        rwlock: usize,
        lgenval: u32,
        ugenval: u32,
        rw_wc: u32,
        flags: u32,
    ) -> Result<usize, Errno> {
        let result = match operation {
            PsynchRwOperation::LongReadLock | PsynchRwOperation::YieldWriteLock => {
                Err(Errno::ESRCH)
            }
            PsynchRwOperation::Upgrade | PsynchRwOperation::Downgrade => Ok(0),
            PsynchRwOperation::Unlock2 => Err(Errno::ENOTSUP),
            PsynchRwOperation::ReadLock => {
                self.psynch_rw_lock(PTH_RW_TYPE_READ, rwlock, lgenval, ugenval, rw_wc, flags)
            }
            PsynchRwOperation::WriteLock => {
                self.psynch_rw_lock(PTH_RW_TYPE_WRITE, rwlock, lgenval, ugenval, rw_wc, flags)
            }
            PsynchRwOperation::Unlock => {
                self.psynch_rw_unlock(rwlock, lgenval, ugenval, rw_wc, flags)
            }
        };
        self.psynch_result(syscall_value(result))
    }

    /// `__psynch_rw_lock`.
    fn psynch_rw_lock(
        &self,
        kind: u32,
        rwlock: usize,
        lgenval: u32,
        ugenval: u32,
        rw_wc: u32,
        flags: u32,
    ) -> Result<u32, Errno> {
        let lockseq = lgenval & PTHRW_COUNT_MASK;
        let (prepost_kind, which) = if kind == PTH_RW_TYPE_READ {
            (KW_UNLOCK_PREPOST_READLOCK, QueueKind::Read)
        } else {
            (KW_UNLOCK_PREPOST_WRLOCK, QueueKind::Write)
        };
        let mut table = self.global.psynch.lock();
        let key = self.psynch_find(
            &mut table,
            rwlock,
            flags,
            Kind::Rwlock,
            lgenval,
            ugenval,
            rw_wc,
        )?;
        let now = self.global.platform.mach_absolute_time();
        let kwq = table.kwq(key);
        kwq.check_init(lgenval);
        // Overlapping readers first: they do not count against the prepost.
        if let Some(granted) = handle_overlap(kwq, kind, lgenval, rw_wc)
            .or_else(|| handle_preposted_wakeup(kwq, prepost_kind, lockseq))
        {
            table.release(key, Some(now));
            return Ok(granted);
        }
        let (mut table, outcome) = self.psynch_block(table, key, which, lgenval, false, None);
        let result = match outcome {
            Blocking::Granted(value) => Ok(value),
            Blocking::Ended(error) | Blocking::Refused(error) => Err(error),
        };
        let now = self.global.platform.mach_absolute_time();
        table.release(key, Some(now));
        result
    }

    /// `_psynch_rw_unlock`: grant the lock to the next readers or writer
    /// once every thread the unlock accounts for has arrived, or prepost it.
    fn psynch_rw_unlock(
        &self,
        rwlock: usize,
        lgenval: u32,
        ugenval: u32,
        rw_wc: u32,
        flags: u32,
    ) -> Result<u32, Errno> {
        let curgen = lgenval & PTHRW_COUNT_MASK;
        let mut table = self.global.psynch.lock();
        let key = self.psynch_find(
            &mut table,
            rwlock,
            flags,
            Kind::Rwlock,
            lgenval,
            ugenval,
            rw_wc,
        )?;
        let now = self.global.platform.mach_absolute_time();
        let kwq = table.kwq(key);
        let isinit = kwq.check_init(lgenval);
        let mut updatebits = 0;
        // An unlock below the last one is spurious.
        if kwq.lastunlockseq == PTHRW_RWL_INIT || !is_seqlower(ugenval, kwq.lastunlockseq) {
            let diff = find_diff(lgenval, ugenval);
            let mut count = 0;
            for queue in [&kwq.read, &kwq.write] {
                count += queue.count_tolowest(curgen);
                if count >= diff {
                    break;
                }
            }
            if count == 0 || count < diff {
                // Not every waiter the unlock accounts for has arrived: the
                // last of them takes the grant.
                if kwq.prepost.sseq & PTH_RWS_SBIT != 0 || is_seqhigher_eq(rw_wc, kwq.prepost.sseq)
                {
                    kwq.mark_preposted_wakeup(diff.wrapping_sub(count), curgen, rw_wc);
                    updatebits = lgenval;
                }
            } else {
                if isinit && kwq.init_cleared {
                    kwq.init_cleared = false;
                }
                kwq.clear_preposted_wakeup();
                (updatebits, _) = handle_unlock(kwq, rw_wc, 0, 0);
            }
        }
        table.release(key, Some(now));
        Ok(updatebits)
    }
}

/// `_ksyn_cvsignal_any`.
fn cvsignal_any<P: ShimPlatform>(
    kwq: &mut Kwq<P>,
    fakes: &mut Fakes,
    uptoseq: u32,
    signalseq: u32,
    updatebits: &mut u32,
    broadcast: &mut bool,
) -> Result<(), Errno> {
    let Some(index) = find_signalseq(&kwq.write, uptoseq, signalseq) else {
        return kwq.prepost_fake(KweState::Prepost, uptoseq, fakes);
    };
    let (state, lockseq) = {
        let kwe = &kwq.write.entries[index];
        (kwe.state, kwe.lockseq)
    };
    match state {
        // A waiter below the signal's own may leave that one without a
        // signal, so wake everyone: spurious wakeups are allowed,
        // starvation is not.
        KweState::InWait if is_seqlower(lockseq, signalseq) => *broadcast = true,
        KweState::InWait => {
            kwq.signal(QueueKind::Write, index, PTH_RWL_MTX_WAIT);
            *updatebits = updatebits.wrapping_add(PTHRW_INC);
        }
        KweState::Prepost => kwq.write.entries[index].count += 1,
        // An existing broadcast covers this signal.
        KweState::Broadcast => {}
    }
    Ok(())
}

/// `_ksyn_cvsignal_thread`: wake `thread` if it waits on this condition
/// variable; otherwise, or if it is outside the signal's range, broadcast.
fn cvsignal_thread<P: ShimPlatform>(
    kwq: &mut Kwq<P>,
    thread: ThreadId,
    uptoseq: u32,
    signalseq: u32,
    updatebits: &mut u32,
    broadcast: &mut bool,
) {
    let Some(index) = kwq
        .write
        .entries
        .iter()
        .position(|kwe| kwe.thread() == Some(thread))
    else {
        *broadcast = true;
        return;
    };
    let lockseq = kwq.write.entries[index].lockseq;
    kwq.signal(QueueKind::Write, index, PTH_RWL_MTX_WAIT);
    if is_seqhigher(lockseq, uptoseq) || is_seqlower(lockseq, signalseq) {
        *broadcast = true;
    } else {
        *updatebits = updatebits.wrapping_add(PTHRW_INC);
    }
}

/// `_kwq_handle_overlap`: a reader arriving while the lock is granted to
/// readers with no writer pending shares the grant.
fn handle_overlap<P: ShimPlatform>(
    kwq: &mut Kwq<P>,
    kind: u32,
    lgenval: u32,
    rw_wc: u32,
) -> Option<u32> {
    if kind != PTH_RW_TYPE_READ
        || !kwq.overlap_guard
        || rw_wc & PTHRW_RWS_SAVEMASK != 0
        || lgenval & PTH_RWL_WBIT != 0
    {
        return None;
    }
    if is_seqlower_eq(rw_wc, kwq.nextseqword) || is_seqhigher_eq(kwq.lastseqword, rw_wc) {
        kwq.nextseqword = kwq.nextseqword.wrapping_add(PTHRW_INC);
        return Some(PTHRW_INC | (kwq.nextseqword & PTHRW_BIT_MASK) | PTH_RWL_MBIT);
    }
    None
}

/// `_kwq_handle_preposted_wakeup`: the last locker an unlock was waiting
/// for arrived; grant the lock now, to it or to the queued threads.
fn handle_preposted_wakeup<P: ShimPlatform>(kwq: &mut Kwq<P>, kind: u32, lseq: u32) -> Option<u32> {
    if kwq.prepost.count == 0 || !is_seqlower_eq(lseq, kwq.prepost.lseq) {
        return None;
    }
    kwq.prepost.count -= 1;
    if kwq.prepost.count > 0 {
        return None;
    }
    let sseq = kwq.prepost.sseq;
    kwq.clear_preposted_wakeup();
    kwq.init_cleared = false;
    let (updatebits, block) = handle_unlock(kwq, sseq, kind | KW_UNLOCK_PREPOST, lseq);
    (!block).then_some(updatebits)
}

/// `kwq_handle_unlock`: grant the lock to the next readers or writer. With
/// a prepost flag, the calling locker at `premgen` takes part; the second
/// value is whether it must still block.
fn handle_unlock<P: ShimPlatform>(
    kwq: &mut Kwq<P>,
    rw_wc: u32,
    flags: u32,
    premgen: u32,
) -> (u32, bool) {
    kwq.lastseqword = rw_wc;
    kwq.lastunlockseq = rw_wc & PTHRW_COUNT_MASK;
    kwq.overlap_guard = false;
    let (rwtype, _, low_writer) = find_rw_lowest(kwq, flags, premgen);
    let mut updatebits = 0;
    let mut block = true;
    match rwtype & PTH_RW_TYPE_MASK {
        PTH_RW_TYPE_READ => {
            let writers = rwtype & PTH_RWSHFT_TYPE_WRITE != 0;
            if writers {
                updatebits |= PTH_RWL_WBIT | PTH_RWL_KBIT;
            }
            let mut needed;
            let mut current_returns = false;
            if writers {
                needed = kwq.read.count_tolowest(low_writer);
                if flags & KW_UNLOCK_PREPOST_READLOCK != 0 && is_seqlower(premgen, low_writer) {
                    current_returns = true;
                    needed += 1;
                }
            } else {
                // Only readers: later readers may overlap this grant.
                kwq.overlap_guard = true;
                needed = u32::try_from(kwq.read.count()).expect("queued threads fit in u32");
                if flags & KW_UNLOCK_PREPOST_READLOCK != 0 {
                    current_returns = true;
                    needed += 1;
                }
            }
            updatebits = updatebits.wrapping_add(needed << PTHRW_COUNT_SHIFT);
            kwq.nextseqword = (rw_wc & PTHRW_COUNT_MASK).wrapping_add(updatebits);
            if current_returns {
                block = false;
            }
            // ksyn_wakeupreaders
            while kwq.read.count() != 0 && (!writers || is_seqlower(kwq.read.firstnum, low_writer))
            {
                kwq.signal(QueueKind::Read, 0, updatebits);
            }
        }
        PTH_RW_TYPE_WRITE => {
            updatebits |= PTHRW_INC | PTH_RWL_KBIT | PTH_RWL_EBIT;
            if flags & KW_UNLOCK_PREPOST_WRLOCK != 0 && low_writer == premgen {
                block = false;
                if kwq.write.count() != 0 {
                    updatebits |= PTH_RWL_WBIT;
                }
            } else {
                // Writers remain after this grant, or the preposting writer
                // waits for a later one.
                if kwq.write.count() > 1 || flags & KW_UNLOCK_PREPOST_WRLOCK != 0 {
                    updatebits |= PTH_RWL_WBIT;
                }
                kwq.signal(QueueKind::Write, 0, updatebits);
            }
            kwq.nextseqword = (rw_wc & PTHRW_COUNT_MASK).wrapping_add(updatebits);
        }
        // Nothing waits and no locker preposts: XNU panics; the callers
        // reach this only after counting a waiter.
        _ => {}
    }
    (updatebits, block)
}
