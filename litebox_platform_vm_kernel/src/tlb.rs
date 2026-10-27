// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! TLB shootdowns, by IPI ([`cpu::Ipi::FlushTlb`]): leaves of a task table
//! that other CPUs may cache stale (present ones that lost a permission or
//! their frame) are flushed there before the change returns, and so before
//! their frames are freed.
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
//! (else it switched since, which flushed), then answers.
//!
//! Unmaps are synchronous: deferring their shootdowns (LATR) also requires
//! deferred frame reclamation and a fence before the runner reuses the range.

use crate::LOCK_WARNING;
use crate::boot;
use crate::cpu::{self, CpuId, MAX_CPUS};
use core::sync::atomic::{AtomicU64, Ordering, fence};
use litebox_platform::time::{Instant as _, TimeProvider as _};
use x86_64::VirtAddr;
use x86_64::instructions::tlb;
use x86_64::registers::control::Cr3;
use x86_64::structures::paging::page::PageRange;
use x86_64::structures::paging::{Page, PhysFrame, Size4KiB};

#[cfg(debug_assertions)]
pub(crate) mod clone_check;

/// Above this many pages, a full flush is cheaper than `invlpg` per page
/// (Linux's `tlb_single_page_flush_ceiling`).
const SINGLE_PAGE_FLUSH_CEILING: u64 = 33;

/// The CPUs that may cache a table's translations: bit `i` for CPU `i` (see
/// the module docs).
#[derive(Default)]
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

/// An initiator's request, from its publication until every target answered.
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

/// The requests and inboxes, which interrupt handlers reach without per-CPU
/// data.
struct Shootdowns {
    /// By initiator.
    requests: [Request; MAX_CPUS],
    /// By target: bit `i`, initiator `i` published a request for it.
    inboxes: [AtomicU64; MAX_CPUS],
    /// See [`clone_check`].
    #[cfg(debug_assertions)]
    clone_check: spin::Once<clone_check::Check>,
}

static SHOOTDOWNS: Shootdowns = Shootdowns {
    requests: [const { Request::new() }; MAX_CPUS],
    inboxes: [const { AtomicU64::new(0) }; MAX_CPUS],
    #[cfg(debug_assertions)]
    clone_check: spin::Once::new(),
};

/// The indices of the bits set in `mask`.
fn indices(mut mask: u64) -> impl Iterator<Item = usize> {
    core::iter::from_fn(move || {
        let index = mask.trailing_zeros();
        mask &= mask.wrapping_sub(1);
        (index < u64::BITS).then_some(index as usize)
    })
}

/// Flushes `pages` of the table whose P4 frame is `root`, which `cpus` may
/// cache, on the calling CPU and on the other online ones in `cpus`, and
/// waits for those. The caller changed the leaves, and holds no spin lock
/// (see the module docs).
pub(crate) fn shootdown(cpus: &Cpus, root: PhysFrame, pages: PageRange<Size4KiB>) {
    // The leaves' changes, then the mask (see the module docs).
    fence(Ordering::SeqCst);
    let me = cpu::current();
    let targets = cpus.0.load(Ordering::SeqCst) & cpu::online_mask() & !me.bit();
    let request = &SHOOTDOWNS.requests[me.index()];
    if targets != 0 {
        debug_assert_eq!(
            request.pending.load(Ordering::Relaxed),
            0,
            "a request pending"
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
        for target in indices(targets) {
            SHOOTDOWNS.inboxes[target].fetch_or(me.bit(), Ordering::SeqCst);
        }
        cpu::request_tlb_flush(targets);
    }
    flush_local(pages);
    if targets != 0 {
        wait(request);
    }
}

/// Until every target answered `request`, taking interrupts, and so other
/// initiators' requests. Warns, once, if that takes [`LOCK_WARNING`]: a
/// deadlock (e.g., a target spins for a lock this CPU holds)?
fn wait(request: &Request) {
    let platform = boot::started().expect("other CPUs are online once started");
    let deadline = platform
        .now()
        .checked_add(LOCK_WARNING)
        .expect("the clock is far from overflowing");
    let mut warned = false;
    loop {
        let pending = request.pending.load(Ordering::Acquire);
        if pending == 0 {
            return;
        }
        if !warned && platform.now() >= deadline {
            litebox_util_log::warn!(
                pending:% = format_args!("{pending:#x}"),
                waited:? = LOCK_WARNING;
                "still waiting for CPUs to flush their TLBs: a deadlock? (see `tlb`)"
            );
            warned = true;
        }
        cpu::relax();
    }
}

/// Handles the requests to `cpu`, the one an external interrupt arrived on,
/// in its handler: no locks, no per-CPU data.
pub(crate) fn handle(cpu: CpuId) {
    let inbox = &SHOOTDOWNS.inboxes[cpu.index()];
    if inbox.load(Ordering::Relaxed) == 0 {
        return;
    }
    let (table, _) = Cr3::read();
    for initiator in indices(inbox.swap(0, Ordering::Acquire)) {
        let request = &SHOOTDOWNS.requests[initiator];
        if request.root.load(Ordering::Relaxed) == table.start_address().as_u64() {
            flush_local(request.pages());
        }
        // After the flush (`invlpg` and CR3 writes serialize), and the reads
        // of the request, which the initiator may then reuse.
        request.pending.fetch_and(!cpu.bit(), Ordering::Release);
    }
}

/// Self-check (debug builds, once [`crate::VmKernel::start_cpus`] started
/// the CPUs): each other online CPU answers a request, through
/// [`cpu::Ipi::FlushTlb`], here of a page of the table at `root`.
pub(crate) fn self_check(root: PhysFrame) {
    let cpus = Cpus(AtomicU64::new(cpu::online_mask()));
    let page = Page::containing_address(VirtAddr::new(crate::USER_ADDR_MIN as u64));
    shootdown(&cpus, root, Page::range(page, page + 1));
}
