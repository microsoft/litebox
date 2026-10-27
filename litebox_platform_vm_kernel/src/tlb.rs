// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TLB shootdowns, by IPI ([`cpu::Ipi::FlushTlb`]): leaves of a task table
//! that other CPUs may cache stale (present ones that lost a permission, or
//! were revoked: a leaf maps another frame only once revoked and flushed, so
//! that no two CPUs translate a page differently) are flushed there before the
//! change returns, and so before their frames are freed.
//!
//! A table's [`Cpus`] (Linux's `mm_cpumask`) has a CPU's bit from before CR3
//! points to the table until after it points elsewhere: with no PCID and no
//! global pages, that CR3 write flushed the CPU's translations. An initiator
//! ([`shootdown`]) changes the leaves, then reads the mask (sequentially
//! consistent): a CPU that loads the table after the read sees the new
//! leaves, one that loaded it before gets a request, and one that left in
//! between answers a harmless one.
//!
//! An initiator publishes its one request (it waits for the last before
//! making another), sends the IPIs (else panics: see
//! [`cpu::request_tlb_flush`]), flushes locally, then waits for every
//! target, taking interrupts ([`cpu::relax`]), so that initiators answer each
//! other. It holds no spin lock meanwhile: a target spinning for one with
//! interrupts disabled would never answer (a process's claim is fine: its
//! waiters take interrupts). Never in an interrupt handler.
//!
//! Every external interrupt first handles its CPU's requests ([`handle`]; one
//! atomic load if none): the CPU flushes if CR3 still points to the table
//! (else it switched since, which flushed), then answers. It answers each
//! request once, at the first interrupt it takes after its publication: an
//! IPI only rings, so a spare one finds nothing to answer, and one interrupt
//! answers all the requests whose IPIs coalesced. So an initiator sends the
//! IPIs again, every [`RESEND`], to the targets yet to answer: a lost IPI
//! (e.g., by a faulty hypervisor) costs a delay, not a hang.
//!
//! Unmaps are synchronous: deferring their shootdowns (LATR) also requires
//! deferred frame reclamation and a fence before the runner reuses the range.

use crate::cpu::{self, CpuId, MAX_CPUS};
use crate::{Instant, boot};
use core::sync::atomic::{AtomicU64, Ordering, fence};
use core::time::Duration;
use litebox_platform::time::{Instant as _, TimeProvider as _};
use x86_64::VirtAddr;
use x86_64::instructions::tlb;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::page::PageRange;
use x86_64::structures::paging::{Page, PhysFrame, Size4KiB};

#[cfg(debug_assertions)]
pub(crate) mod clone_check;
#[cfg(test)]
mod tests;

/// Above this many pages, a full flush is cheaper than `invlpg` per page
/// (Linux's `tlb_single_page_flush_ceiling`).
const SINGLE_PAGE_FLUSH_CEILING: u64 = 33;

/// How long an initiator waits for its targets before it sends the IPIs
/// again to those yet to answer (see the module docs): many times an
/// answer's usual time (tens of microseconds, under nested KVM too), so that
/// it seldom sends one needlessly, which costs the target an interrupt.
const RESEND: Duration = Duration::from_millis(1);

/// How long an initiator waits for its targets before it warns, once per
/// wait: far beyond an answer's usual time, even with [`RESEND`]s. But a host
/// may not run a target's vCPU for that long (e.g., when overloaded): the
/// warning tells of a slow shootdown, not of a deadlock.
const TLB_WARNING: Duration = Duration::from_millis(100);

/// The CPUs that may cache a table's translations: bit `i` for CPU `i` (see
/// the module docs). On a cache line of its own, so that CPUs switching to or
/// from the table do not contend with the table's lock, which faults and
/// mapping changes take.
#[derive(Default)]
#[repr(align(64))]
pub(crate) struct Cpus(AtomicU64);

impl Cpus {
    /// Before the calling CPU, `cpu`, points CR3 to the table.
    pub(crate) fn enter(&self, cpu: CpuId) {
        self.0.fetch_or(cpu.bit(), Ordering::SeqCst);
    }

    /// Once the calling CPU, `cpu`, points CR3 elsewhere.
    pub(crate) fn leave(&self, cpu: CpuId) {
        self.0.fetch_and(!cpu.bit(), Ordering::SeqCst);
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.load(Ordering::SeqCst) == 0
    }
}

/// Flushes `pages` of the table CR3 points to, on the calling CPU.
fn flush_local(pages: PageRange<Size4KiB>) {
    if pages.len() <= SINGLE_PAGE_FLUSH_CEILING {
        pages.for_each(|page| tlb::flush(page.start_address()));
    } else {
        tlb::flush_all();
    }
}

/// What the requests and answers need of the CPU they run on: the calling
/// one ([`ThisCpu`]), or a host test's.
trait Cpu {
    /// Which CPU it is.
    fn id(&self) -> CpuId;
    /// The P4 frame of the table it uses (CR3's).
    fn table(&self) -> PhysFrame;
    /// Flushes `pages` of that table.
    fn flush(&self, pages: PageRange<Size4KiB>);
    /// Sends [`cpu::Ipi::FlushTlb`] to `cpus` (bit `i`: CPU `i`).
    fn request_flush(&self, cpus: u64);
    /// A step of a wait: takes the pending interrupts.
    fn relax(&self);
    /// The kernel clock's time.
    fn now(&self) -> Instant;
}

/// The calling CPU.
struct ThisCpu(CpuId);

impl Cpu for ThisCpu {
    fn id(&self) -> CpuId {
        self.0
    }

    fn table(&self) -> PhysFrame {
        Cr3::read().0
    }

    fn flush(&self, pages: PageRange<Size4KiB>) {
        flush_local(pages);
    }

    fn request_flush(&self, cpus: u64) {
        cpu::request_tlb_flush(cpus);
    }

    fn relax(&self) {
        cpu::relax();
    }

    fn now(&self) -> Instant {
        boot::started()
            .expect("other CPUs are online once started")
            .now()
    }
}

/// An initiator's request, from its publication until every target answered.
/// On a cache line of its own, so that other initiators' shootdowns do not
/// contend with it.
#[repr(align(64))]
struct Request {
    /// The address of the table's P4 frame.
    root: AtomicU64,
    /// The pages, as addresses.
    start: AtomicU64,
    end: AtomicU64,
    /// Bit `i`: CPU `i` has yet to answer.
    pending: AtomicU64,
}

impl Request {
    const fn new() -> Self {
        Self {
            root: AtomicU64::new(0),
            start: AtomicU64::new(0),
            end: AtomicU64::new(0),
            pending: AtomicU64::new(0),
        }
    }

    fn pages(&self) -> PageRange<Size4KiB> {
        let page = |address: &AtomicU64| {
            Page::containing_address(VirtAddr::new_truncate(address.load(Ordering::Relaxed)))
        };
        Page::range(page(&self.start), page(&self.end))
    }
}

/// A target's inbox: bit `i`, initiator `i` published a request for it. On a
/// cache line of its own, so that shootdowns of other targets do not contend
/// with it.
#[repr(align(64))]
struct Inbox(AtomicU64);

/// The requests and inboxes, which interrupt handlers reach without per-CPU
/// data.
struct Shootdowns {
    /// By initiator.
    requests: [Request; MAX_CPUS],
    /// By target.
    inboxes: [Inbox; MAX_CPUS],
    /// See [`clone_check`].
    #[cfg(debug_assertions)]
    clone_check: spin::Once<clone_check::Check>,
}

impl Shootdowns {
    const fn new() -> Self {
        Self {
            requests: [const { Request::new() }; MAX_CPUS],
            inboxes: [const { Inbox(AtomicU64::new(0)) }; MAX_CPUS],
            #[cfg(debug_assertions)]
            clone_check: spin::Once::new(),
        }
    }
}

static SHOOTDOWNS: Shootdowns = Shootdowns::new();

/// Flushes `pages` of the table whose P4 frame is `root`, which `cpus` may
/// cache, on the calling CPU and on the other online ones in `cpus`, and
/// waits for those. The caller changed the leaves, and holds no spin lock
/// (see the module docs).
pub(crate) fn shootdown(cpus: &Cpus, root: PhysFrame, pages: PageRange<Size4KiB>) {
    // The leaves' changes, then the mask (see the module docs).
    fence(Ordering::SeqCst);
    let me = cpu::current();
    let targets = cpus.0.load(Ordering::SeqCst) & cpu::online_mask() & !me.bit();
    initiate(&SHOOTDOWNS, &ThisCpu(me), targets, root, pages);
}

/// [`shootdown`], on `this` CPU, of the other CPUs `targets` (bit `i`: CPU
/// `i`), with the requests and inboxes of `shootdowns`.
fn initiate(
    shootdowns: &Shootdowns,
    this: &impl Cpu,
    targets: u64,
    root: PhysFrame,
    pages: PageRange<Size4KiB>,
) {
    let me = this.id();
    let request = &shootdowns.requests[me.index()];
    if targets != 0 {
        // In release builds too: a nested shootdown (e.g., from an interrupt
        // taken as this CPU waits) would overwrite the pending request, whose
        // wait would then end before its targets flushed.
        assert_eq!(
            request.pending.load(Ordering::Relaxed),
            0,
            "nested TLB shootdown on CPU {me}"
        );
        request
            .root
            .store(root.start_address().as_u64(), Ordering::Relaxed);
        request
            .start
            .store(pages.start.start_address().as_u64(), Ordering::Relaxed);
        request
            .end
            .store(pages.end.start_address().as_u64(), Ordering::Relaxed);
        request.pending.store(targets, Ordering::Relaxed);
        // Publishes the request: `handle` acquires it from the inbox.
        for target in cpu::cpus_in(targets) {
            shootdowns.inboxes[target.index()]
                .0
                .fetch_or(me.bit(), Ordering::SeqCst);
        }
        this.request_flush(targets);
    }
    this.flush(pages);
    if targets != 0 {
        wait(this, request);
    }
}

/// Until every target answered `request`, taking interrupts, and so other
/// initiators' requests, and sending the IPIs again every [`RESEND`] to the
/// targets yet to answer. Warns, once, if that takes [`TLB_WARNING`], and then
/// logs how long it took once it ends: a warning with no such line is for a
/// wait that has not ended.
fn wait(this: &impl Cpu, request: &Request) {
    let after = |instant: Instant, duration| {
        instant
            .checked_add(duration)
            .expect("the clock is far from overflowing")
    };
    let start = this.now();
    let waited = |now: Instant| now.checked_duration_since(&start).unwrap_or_default();
    let deadline = after(start, TLB_WARNING);
    let mut resend = after(start, RESEND);
    let mut warned = false;
    loop {
        let pending = request.pending.load(Ordering::Acquire);
        if pending == 0 {
            if warned {
                litebox_util_log::info!(
                    cpu:% = this.id(),
                    waited:? = waited(this.now());
                    "slow TLB shootdown done"
                );
            }
            return;
        }
        let now = this.now();
        if now >= resend {
            this.request_flush(pending);
            resend = after(now, RESEND);
        }
        if !warned && now >= deadline {
            litebox_util_log::warn!(
                cpu:% = this.id(),
                pending:% = format_args!("{pending:#x}"),
                waited:? = waited(now);
                "slow TLB shootdown, waiting for the CPUs `pending` (bit `i`: CPU `i`): not run \
                 by the host (e.g., overloaded), or, if this never ends, one spins with \
                 interrupts disabled (e.g., for a lock this CPU holds; see `tlb`)"
            );
            warned = true;
        }
        this.relax();
    }
}

/// Handles the requests to `cpu`, the one an external interrupt arrived on,
/// in its handler: no locks, no per-CPU data.
pub(crate) fn handle(cpu: CpuId) {
    answer(&SHOOTDOWNS, &ThisCpu(cpu));
}

/// [`handle`], on `this` CPU, with the requests and inboxes of `shootdowns`.
fn answer(shootdowns: &Shootdowns, this: &impl Cpu) {
    let me = this.id();
    let inbox = &shootdowns.inboxes[me.index()].0;
    if inbox.load(Ordering::Relaxed) == 0 {
        return;
    }
    let table = this.table();
    for initiator in cpu::cpus_in(inbox.swap(0, Ordering::Acquire)) {
        let request = &shootdowns.requests[initiator.index()];
        if request.root.load(Ordering::Relaxed) == table.start_address().as_u64() {
            this.flush(request.pages());
        }
        // After the flush (`invlpg` and CR3 writes serialize), and the reads
        // of the request, which the initiator may then reuse.
        request.pending.fetch_and(!me.bit(), Ordering::Release);
    }
}

/// Self-check (debug builds, once [`crate::VmKernel::start_cpus`] started
/// the CPUs): each other online CPU answers a request, through
/// [`cpu::Ipi::FlushTlb`], here of a page of the table at `root`.
#[cfg(debug_assertions)]
pub(crate) fn self_check(root: PhysFrame) {
    let cpus = Cpus(AtomicU64::new(cpu::online_mask()));
    let page = Page::containing_address(VirtAddr::new(crate::USER_ADDR_MIN as u64));
    shootdown(&cpus, root, Page::range(page, page + 1));
}
