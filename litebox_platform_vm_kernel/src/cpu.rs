// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The CPUs: the boot CPU, and those [`VmKernel::start_cpus`] starts, each
//! with a dense index ([`CpuId`]; the boot CPU's is 0) and a local APIC ID
//! ([`apic_id`]), for IPIs.
//!
//! An idle CPU halts ([`halt`]). [`wake`], [`wake_idle`] and [`notify_all`]
//! mark CPUs, and end the halts of those idle with the runner's wake IPI
//! ([`InterruptController`]); [`notify_all`] also tells busy CPUs
//! ([`take_notified`]). No wakeup is lost: a halt marks its CPU idle, then
//! halts unless it was marked; a waker marks, then sends the IPI to those idle
//! (all sequentially consistent). Only the loop a CPU runs (e.g., its
//! scheduler) clears its marks ([`acknowledge`], [`take_notified`]), before it
//! looks again at what it was woken for; until then, its halts return at once,
//! taking only the pending interrupts (e.g., a driver's, which then polls).
//! Wakers publish what they wake for first; halts may also end spuriously:
//! check for work before halting, and again after.
//!
//! Takes no locks, and only [`current`] (so [`halt`], [`marked`],
//! [`acknowledge`], [`take_notified`] and `set_suspended`) touches per-CPU
//! data: [`wake`], [`wake_idle`] and [`notify_all`] are usable in interrupt
//! handlers.
//!
//! The kernel clock ([`crate::clock`]) is the TSC of whichever CPU reads it:
//! the CPUs' TSCs are assumed synchronized, unchecked (VMMs such as QEMU and
//! KVM normally keep them so, but need not).

use crate::VmKernel;
use crate::per_cpu::with_per_cpu_variables;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// At most this many CPUs run; any others are not started.
pub const MAX_CPUS: usize = 64;
const _: () = assert!(MAX_CPUS <= u64::BITS as usize);

/// A CPU's dense index: the boot CPU's is 0; [`VmKernel::start_cpus`]
/// numbers the others in the order it starts them.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CpuId(u8);

impl CpuId {
    /// The boot CPU's.
    pub const BOOT: Self = Self(0);

    /// The CPU with index `index`; `None` from [`MAX_CPUS`] up.
    pub fn new(index: usize) -> Option<Self> {
        u8::try_from(index)
            .ok()
            .filter(|_| index < MAX_CPUS)
            .map(Self)
    }

    /// Below [`MAX_CPUS`], e.g., for per-CPU arrays.
    pub const fn index(self) -> usize {
        self.0 as usize
    }

    pub(crate) const fn bit(self) -> u64 {
        1 << self.0
    }
}

impl core::fmt::Display for CpuId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        self.0.fmt(f)
    }
}

/// An IPI to a CPU; see [`InterruptController::send_ipi`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ipi {
    /// Resets the CPU to wait for a startup IPI.
    Init,
    /// Starts a CPU that waits for one, in real mode at physical address
    /// `page << 12`.
    Startup { page: u8 },
    /// The runner's wake vector, whose handler only ends the interrupt.
    Wake,
    /// The runner's TLB-flush vector, whose handler only ends the interrupt,
    /// a doorbell ([`crate::Handled::Doorbell`]): the platform handles the
    /// flushes before calling it.
    FlushTlb,
}

/// The runner's interrupt controller (e.g., the local APICs), for starting
/// and waking CPUs.
///
/// # Safety
///
/// [`Self::send_ipi`] sends exactly `ipi` to exactly the CPU with local APIC
/// ID `apic_id`, or sends nothing and returns false; [`Self::init_cpu`]
/// touches only the calling CPU's interrupt controller.
/// [`VmKernel::start_cpus`] relies on them to start only the CPUs it means
/// to, only in its trampoline.
pub unsafe trait InterruptController: Sync {
    /// On each CPU [`VmKernel::start_cpus`] starts, before it is online:
    /// enables its interrupt controller as the boot CPU's is (e.g., the local
    /// APIC's mode, spurious vector, and timer).
    fn init_cpu(&self);

    /// Sends `ipi` from the calling CPU to the one with local APIC ID
    /// `apic_id`; false if it cannot address that CPU alone (then sends
    /// nothing). Interrupt handlers send [`Ipi::Wake`] too: no locks, no
    /// per-CPU data, and any waiting bounded.
    ///
    /// # Safety
    ///
    /// For [`Ipi::Init`] and [`Ipi::Startup`], the CPU must be one the caller
    /// starts, running nothing anything still needs, and, for the latter,
    /// the page must hold the code it is to run in real mode, with its data,
    /// from then on (see [`VmKernel::start_cpus`]: for good). [`Ipi::Wake`]
    /// and [`Ipi::FlushTlb`] need nothing.
    unsafe fn send_ipi(&self, apic_id: u32, ipi: Ipi) -> bool;
}

/// What a CPU [`VmKernel::start_cpus`] starts runs once online, with
/// interrupts disabled; it never returns.
pub type CpuEntry = fn(&'static VmKernel, CpuId) -> !;

/// The CPUs' shared state: lock-free, so that interrupt handlers may wake
/// CPUs.
struct Cpus {
    /// Bit `i`: CPU `i` is online. The boot CPU is from the start.
    online: AtomicU64,
    /// Bit `i`: CPU `i` is in [`halt`].
    idle: AtomicU64,
    /// Bit `i`: CPU `i` was woken since it last [acknowledged](acknowledge);
    /// until then, its halts return at once. Set busy or not: a CPU about to
    /// halt may not be idle yet.
    woken: AtomicU64,
    /// Bit `i`: CPU `i` was notified since it last
    /// [acknowledged](acknowledge) or [took](take_notified) it; as `woken`
    /// for halts.
    notified: AtomicU64,
    /// Index to local APIC ID, set before the CPU is online.
    apic_ids: [AtomicU32; MAX_CPUS],
    /// Bit `i`: CPU `i`'s work suspended: set once it first suspends, until
    /// it finishes (also while resumed); see
    /// [`crate::worker::interrupt_suspended`].
    suspended: AtomicU64,
    /// Set by [`VmKernel::start_cpus`]; until then, no IPIs are sent.
    controller: spin::Once<&'static dyn InterruptController>,
}

static CPUS: Cpus = Cpus {
    online: AtomicU64::new(CpuId::BOOT.bit()),
    idle: AtomicU64::new(0),
    woken: AtomicU64::new(0),
    notified: AtomicU64::new(0),
    apic_ids: [const { AtomicU32::new(0) }; MAX_CPUS],
    suspended: AtomicU64::new(0),
    controller: spin::Once::new(),
};

/// The calling CPU. Not for interrupt handlers (it reads per-CPU data).
pub fn current() -> CpuId {
    with_per_cpu_variables(|pcv| pcv.cpu)
}

/// Bit `i` for each online CPU `i`.
pub fn online_mask() -> u64 {
    CPUS.online.load(Ordering::SeqCst)
}

/// How many CPUs are online.
pub fn online_count() -> usize {
    online_mask().count_ones() as usize
}

/// The online CPUs, in order. Once online, a CPU stays online.
pub fn online() -> impl Iterator<Item = CpuId> {
    cpus_in(online_mask())
}

/// The CPUs in `mask` (bit `i`: CPU `i`), in order.
pub(crate) fn cpus_in(mut mask: u64) -> impl Iterator<Item = CpuId> {
    core::iter::from_fn(move || {
        // Once `mask` is empty, 64: no CPU's index, which ends the iteration.
        let index = mask.trailing_zeros() as usize;
        mask &= mask.wrapping_sub(1);
        CpuId::new(index)
    })
}

/// `cpu`'s local APIC ID, once it is online.
pub fn apic_id(cpu: CpuId) -> u32 {
    CPUS.apic_ids[cpu.index()].load(Ordering::Relaxed)
}

pub(crate) fn set_apic_id(cpu: CpuId, apic_id: u32) {
    CPUS.apic_ids[cpu.index()].store(apic_id, Ordering::Relaxed);
}

pub(crate) fn set_online(cpu: CpuId) {
    CPUS.online.fetch_or(cpu.bit(), Ordering::SeqCst);
}

/// # Panics
///
/// On a second call.
pub(crate) fn set_controller(controller: &'static dyn InterruptController) {
    let mut installed = false;
    CPUS.controller.call_once(|| {
        installed = true;
        controller
    });
    assert!(installed, "the interrupt controller is already set");
}

/// The one [`VmKernel::start_cpus`] set, if any.
pub(crate) fn controller() -> Option<&'static dyn InterruptController> {
    CPUS.controller.get().copied()
}

/// Halts the calling CPU until an interrupt, with interrupts enabled only for
/// the halt, or until it is woken ([`wake`], [`wake_idle`], [`notify_all`]):
/// at once while it is marked (see [`acknowledge`]), taking the pending
/// interrupts ([`relax`]), or if an interrupt became pending while they were
/// disabled. Clears no mark. May return spuriously: check for work first,
/// and again after.
pub fn halt() {
    let bit = current().bit();
    CPUS.idle.fetch_or(bit, Ordering::SeqCst);
    if marks() & bit == 0 {
        x86_64::instructions::interrupts::enable_and_hlt();
        x86_64::instructions::interrupts::disable();
    } else {
        relax();
    }
    // A waker that then finds this CPU busy sends no IPI: its mark ends the
    // next halt at once.
    CPUS.idle.fetch_and(!bit, Ordering::SeqCst);
}

/// A step of a spin wait (e.g., for a lock, or for another CPU): takes the
/// pending interrupts if they are disabled (handlers neither lock nor touch
/// per-CPU data but the CPU's ID, see [`crate::set_interrupt_handler`]), so
/// that a CPU spinning with them disabled delays none for long (e.g., a
/// device's, which the boot CPU forwards to the others), then hints the spin.
/// Sound only once the calling CPU's IDT is loaded (so not as it starts,
/// before then).
pub fn relax() {
    if !x86_64::instructions::interrupts::are_enabled() {
        // Safety: takes the pending interrupts (after the one instruction
        // STI defers them for), through the loaded IDT, whose handlers
        // neither lock nor touch per-CPU data but the CPU's ID, which never
        // changes; not `nomem`: they may write memory.
        unsafe { core::arch::asm!("sti", "nop", "cli", options(nostack)) };
    }
    core::hint::spin_loop();
}

/// Whether the calling CPU is marked (see [`acknowledge`]), so that its
/// halts return at once, e.g., for a driver to poll without arming a timer.
pub fn marked() -> bool {
    marks() & current().bit() != 0
}

/// Bit `i`: CPU `i` is marked, woken or notified.
fn marks() -> u64 {
    CPUS.woken.load(Ordering::SeqCst) | CPUS.notified.load(Ordering::SeqCst)
}

/// Clears the calling CPU's marks, for the scheduler, before it looks for
/// work (e.g., what its services wait for, and the processes): a wakeup
/// after marks it again, and its next halt returns at once.
pub fn acknowledge() {
    let bit = current().bit();
    CPUS.woken.fetch_and(!bit, Ordering::SeqCst);
    CPUS.notified.fetch_and(!bit, Ordering::SeqCst);
}

/// Whether the calling CPU was notified ([`notify_all`]) since it last
/// acknowledged it, which this does, e.g., for a busy CPU to look again at
/// what it waits for.
pub fn take_notified() -> bool {
    let bit = current().bit();
    CPUS.notified.load(Ordering::Relaxed) & bit != 0
        && CPUS.notified.fetch_and(!bit, Ordering::SeqCst) & bit != 0
}

/// Wakes `cpu` if it is idle (in [`halt`]); if not, its halts return at once
/// until it acknowledges it.
pub fn wake(cpu: CpuId) {
    signal(&CPUS.woken, cpu.bit());
}

/// Wakes the idle CPUs (in [`halt`]) but `except`, e.g., for work any CPU
/// could take: `except` looks for work again itself (e.g., the calling CPU,
/// or the one an interrupt handler runs on), and its halts do not return at
/// once for this. Busy CPUs are not interrupted, but marked, as by [`wake`].
pub fn wake_idle(except: CpuId) {
    signal(&CPUS.woken, !except.bit());
}

/// Notifies every CPU ([`take_notified`]), waking the idle ones, e.g., for an
/// event that may end what any CPU waits for.
pub fn notify_all() {
    signal(&CPUS.notified, u64::MAX);
}

/// Marks `cpus` in `set`, then sends the wake IPI to those idle.
fn signal(set: &AtomicU64, cpus: u64) {
    set.fetch_or(cpus, Ordering::SeqCst);
    interrupt(CPUS.idle.load(Ordering::SeqCst) & cpus);
}

/// Sends the wake IPI to `cpus` (bit `i`: CPU `i`), busy or idle, marking
/// none: e.g., for those in user mode to enter the kernel. Nothing before
/// [`VmKernel::start_cpus`].
pub(crate) fn interrupt(mut cpus: u64) {
    // Harmless if unsent: before `start_cpus`, no other CPU runs, and it
    // never starts one the controller cannot address.
    send(cpus, Ipi::Wake);
}

/// Sends [`Ipi::FlushTlb`] to `cpus` (bit `i`: CPU `i`), for
/// [`crate::tlb`], which then waits for each to answer.
///
/// # Panics
///
/// If it cannot send one (e.g., with no controller): that CPU would never
/// answer, and the caller must not go on without it (e.g., to free frames).
pub(crate) fn request_tlb_flush(cpus: u64) {
    let unsent = send(cpus, Ipi::FlushTlb);
    assert!(
        unsent == 0,
        "TLB-flush IPIs not sent to CPUs {unsent:#x} (bit `i`: CPU `i`)"
    );
}

/// Sends `ipi`, one that needs nothing (see
/// [`InterruptController::send_ipi`]), to `cpus`; returns those it could not
/// send it to: all before [`VmKernel::start_cpus`] sets the controller.
fn send(cpus: u64, ipi: Ipi) -> u64 {
    let Some(controller) = controller() else {
        return cpus;
    };
    let mut unsent = 0;
    for cpu in cpus_in(cpus) {
        // Safety: a wake or TLB-flush IPI (see the callers).
        if !unsafe { controller.send_ipi(apic_id(cpu), ipi) } {
            unsent |= cpu.bit();
        }
    }
    unsent
}

/// Whether `cpu` is in [`halt`].
pub(crate) fn is_idle(cpu: CpuId) -> bool {
    CPUS.idle.load(Ordering::SeqCst) & cpu.bit() != 0
}

/// Bit `i`: CPU `i`'s work suspended, and has not finished (see
/// [`crate::worker::interrupt_suspended`]).
pub(crate) fn suspended_mask() -> u64 {
    CPUS.suspended.load(Ordering::SeqCst)
}

/// Sets the calling CPU's bit in [`suspended_mask`], or clears it.
pub(crate) fn set_suspended(suspended: bool) {
    let bit = current().bit();
    if suspended {
        CPUS.suspended.fetch_or(bit, Ordering::SeqCst);
    } else {
        CPUS.suspended.fetch_and(!bit, Ordering::SeqCst);
    }
}
