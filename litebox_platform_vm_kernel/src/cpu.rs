// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! The CPUs: the boot CPU, and those [`VmKernel::start_cpus`] starts, each
//! with a dense index ([`CpuId`]; the boot CPU's is 0) and a local APIC ID
//! ([`apic_id`]), for IPIs.
//!
//! An idle CPU halts ([`halt`]); [`wake`] ends its halt with the runner's
//! wake IPI ([`InterruptController`]). No wakeup is lost: a halt marks its
//! CPU idle, then halts unless it was marked woken; a waker marks the CPU
//! woken, then sends the IPI if it is idle (all sequentially consistent). So
//! either the halt sees the mark, or the waker sees the CPU idle, and its
//! IPI, pending while interrupts are disabled, ends the halt.
//!
//! Only the loop a CPU runs (e.g., its scheduler) clears its mark
//! ([`acknowledge`]), before it looks again at what it was woken for (as
//! does a CPU coming online, for its own wait); halts never do. So a halt
//! within its look (e.g., a driver's, waiting for a device) cannot lose a
//! wakeup meant for it: such a halt just returns at once until then, and its
//! caller polls. Wakers publish what they wake for first; halts may also end
//! spuriously: check for work before halting, and again after.
//!
//! Lock-free, and only [`current`] (so [`halt`] and [`acknowledge`]) touches
//! per-CPU data: [`wake`] is usable in interrupt handlers. From one that
//! interrupted a halt, it sends that CPU the IPI too, which it takes before
//! the halt ends.
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

    const fn bit(self) -> u64 {
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
    /// needs nothing.
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
    /// Index to local APIC ID, set before the CPU is online.
    apic_ids: [AtomicU32; MAX_CPUS],
    /// Set by [`VmKernel::start_cpus`]; until then, no IPIs are sent.
    controller: spin::Once<&'static dyn InterruptController>,
}

static CPUS: Cpus = Cpus {
    online: AtomicU64::new(CpuId::BOOT.bit()),
    idle: AtomicU64::new(0),
    woken: AtomicU64::new(0),
    apic_ids: [const { AtomicU32::new(0) }; MAX_CPUS],
    controller: spin::Once::new(),
};

/// The calling CPU. Not for interrupt handlers (it reads per-CPU data).
pub fn current() -> CpuId {
    with_per_cpu_variables(|pcv| pcv.cpu)
}

/// The online CPUs, in order. Once online, a CPU stays online.
pub fn online() -> impl Iterator<Item = CpuId> {
    let mask = CPUS.online.load(Ordering::SeqCst);
    (0..MAX_CPUS)
        .filter(move |&i| mask & (1 << i) != 0)
        .filter_map(CpuId::new)
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
/// the halt, or until it is woken ([`wake`]): at once while it is marked
/// woken (see [`acknowledge`]), or if an interrupt became pending while they
/// were disabled. Clears no mark. May return spuriously: check for work
/// first, and again after.
pub fn halt() {
    let bit = current().bit();
    CPUS.idle.fetch_or(bit, Ordering::SeqCst);
    if CPUS.woken.load(Ordering::SeqCst) & bit == 0 {
        x86_64::instructions::interrupts::enable_and_hlt();
        x86_64::instructions::interrupts::disable();
    }
    // A waker that then finds this CPU busy sends no IPI: its mark ends the
    // next halt at once.
    CPUS.idle.fetch_and(!bit, Ordering::SeqCst);
}

/// Clears the calling CPU's mark, before it looks for work (e.g., what it
/// was woken for): a wakeup after marks it again, and its next halt returns
/// at once.
pub fn acknowledge() {
    CPUS.woken.fetch_and(!current().bit(), Ordering::SeqCst);
}

/// Wakes `cpu` if it is idle (in [`halt`]); if not, its halts return at once
/// until it acknowledges it.
pub fn wake(cpu: CpuId) {
    CPUS.woken.fetch_or(cpu.bit(), Ordering::SeqCst);
    if is_idle(cpu)
        && let Some(controller) = controller()
    {
        // Safety: a wake IPI.
        unsafe { controller.send_ipi(apic_id(cpu), Ipi::Wake) };
    }
}

/// Whether `cpu` is in [`halt`].
pub(crate) fn is_idle(cpu: CpuId) -> bool {
    CPUS.idle.load(Ordering::SeqCst) & cpu.bit() != 0
}
