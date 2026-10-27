// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Kernel-grade synchronization: code that may run with interrupts enabled
//! (e.g., the kernel's broker work) takes the locks it shares with the rest of
//! the kernel with interrupts disabled ([`NoPreempt`]), as kernel code always
//! does. So no holder of one is ever interrupted, nor preempted: a CPU never
//! spins for a lock that a preempted holder keeps, and an interrupt handler
//! never finds its own CPU holding one. A section that holds one is a leaf:
//! it neither blocks nor runs code that may take a lock of the code that runs
//! with interrupts enabled.
//!
//! Types keep the rule, not their callers: such a lock is a [`KernelMutex`],
//! whose guard keeps interrupts disabled, and a kernel thread reads its CPU's
//! variables only in a closure that runs with them disabled (`kthread`'s
//! `with_this_cpu`), but for itself, read in one load (`kthread`'s
//! `current`). Only a boundary that no such type covers takes a
//! [`NoPreempt`] itself (e.g., the allocator's entry points, whose locks are
//! upstream's), or a walk that takes a kernel-grade lock once per page: in
//! one section, which [`KernelMutex::lock_in`] borrows.

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
#[cfg(all(debug_assertions, not(test)))]
use core::sync::atomic::{AtomicU8, Ordering};
use spin::mutex::{SpinMutex, SpinMutexGuard};

/// Interrupts disabled, so that the calling code is neither interrupted nor
/// preempted until this drops, which enables them again only if they were as
/// the first of the calling code's live ones began: one taken meanwhile stays
/// pending until then. They nest, and may drop in any order: a kernel thread
/// counts its own (`kthread`'s `begin_section`), and other code runs with
/// interrupts disabled. Valid as the boot CPU starts, before its per-CPU
/// variables are installed, and once a CPU's are, but not on another CPU
/// before then (which takes none). This crate's host tests run in user mode,
/// where `cli` faults: there it changes nothing. `cfg(test)` is per crate, so
/// other crates' host tests must not reach one (e.g., bvk's `serving` stubs
/// its word).
#[must_use = "interrupts are enabled again as it drops"]
pub struct NoPreempt {
    /// Interrupts were enabled as it began; for one no thread counts.
    enabled: bool,
    /// The running kernel thread counts it among its sections.
    counted: bool,
    /// Not `Send`: it restores the state of the code that took it.
    _code: PhantomData<*const ()>,
}

impl NoPreempt {
    pub fn new() -> Self {
        let enabled = disable();
        Self {
            enabled,
            counted: crate::kthread::begin_section(enabled),
            _code: PhantomData,
        }
    }
}

/// Disables interrupts, but in this crate's host tests: whether they were
/// enabled.
fn disable() -> bool {
    if cfg!(test) {
        return false;
    }
    let enabled = x86_64::instructions::interrupts::are_enabled();
    x86_64::instructions::interrupts::disable();
    enabled
}

impl Default for NoPreempt {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoPreempt {
    fn drop(&mut self) {
        let enable = if self.counted {
            crate::kthread::end_section()
        } else {
            self.enabled
        };
        if enable {
            x86_64::instructions::interrupts::enable();
        }
    }
}

/// A kernel thread's live [`NoPreempt`]s, in its control block, so that they
/// go with it from CPU to CPU (it may stop in one): only the last to end
/// enables interrupts again, if they were enabled as the first began.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Sections {
    live: u32,
    enable: bool,
}

impl Sections {
    /// One begins, interrupts having been `enabled`.
    pub(crate) fn begin(&mut self, enabled: bool) {
        if self.live == 0 {
            self.enable = enabled;
        }
        self.live += 1;
    }

    /// One ends: whether to enable interrupts again.
    pub(crate) fn end(&mut self) -> bool {
        self.live -= 1;
        self.live == 0 && self.enable
    }
}

/// A spin lock that kernel code shares with code that may run with interrupts
/// enabled (see the [module](self) docs): taken only with them disabled,
/// which its guard keeps until it drops. Debug builds check that no CPU takes
/// one it holds (it would spin forever), which needs the CPU's per-CPU
/// variables: not in this crate's host tests, which have no CPUs (other
/// crates' host tests would check, and take the guard: see [`NoPreempt`]).
pub struct KernelMutex<T: ?Sized> {
    /// Debug builds: the index of the CPU holding it, or [`NO_OWNER`].
    #[cfg(all(debug_assertions, not(test)))]
    owner: AtomicU8,
    inner: SpinMutex<T>,
}

/// [`KernelMutex::owner`]: no CPU's.
#[cfg(all(debug_assertions, not(test)))]
const NO_OWNER: u8 = u8::MAX;

impl<T> KernelMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            #[cfg(all(debug_assertions, not(test)))]
            owner: AtomicU8::new(NO_OWNER),
            inner: SpinMutex::new(value),
        }
    }
}

impl<T: Default> Default for KernelMutex<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T: ?Sized> KernelMutex<T> {
    /// Spins, with interrupts disabled, until it takes the lock.
    ///
    /// # Panics
    ///
    /// Debug builds: if the calling CPU holds it.
    pub fn lock(&self) -> KernelMutexGuard<'_, T> {
        // Every kernel-grade lock's one boundary: the guard keeps it.
        let no_preempt = NoPreempt::new();
        #[cfg(all(debug_assertions, not(test)))]
        let cpu = self.check_owner();
        let guard = self.inner.lock();
        #[cfg(all(debug_assertions, not(test)))]
        self.owner.store(cpu, Ordering::Relaxed);
        KernelMutexGuard {
            guard,
            #[cfg(all(debug_assertions, not(test)))]
            owner: &self.owner,
            _no_preempt: no_preempt,
        }
    }

    /// Takes the lock as [`Self::lock`] does, but inside `section`, whose
    /// borrow keeps interrupts disabled for as long as the guard lives: so a
    /// walk that takes the lock once per page disables them once, not once per
    /// page.
    ///
    /// # Panics
    ///
    /// Debug builds: if the calling CPU holds it.
    pub fn lock_in<'a>(&'a self, _section: &'a NoPreempt) -> KernelMutexSectionGuard<'a, T> {
        #[cfg(all(debug_assertions, not(test)))]
        let cpu = self.check_owner();
        let guard = self.inner.lock();
        #[cfg(all(debug_assertions, not(test)))]
        self.owner.store(cpu, Ordering::Relaxed);
        KernelMutexSectionGuard {
            guard,
            #[cfg(all(debug_assertions, not(test)))]
            owner: &self.owner,
            _section: PhantomData,
        }
    }

    /// Debug builds: the calling CPU's index, which must not hold the lock.
    #[cfg(all(debug_assertions, not(test)))]
    fn check_owner(&self) -> u8 {
        let cpu = u8::try_from(crate::cpu::current().index()).expect("CPU indices fit a byte");
        assert_ne!(
            self.owner.load(Ordering::Relaxed),
            cpu,
            "a CPU takes a kernel lock it holds"
        );
        cpu
    }
}

/// See [`KernelMutex::lock`]: releases the lock, then restores interrupts.
pub struct KernelMutexGuard<'a, T: ?Sized> {
    // Dropped in this order.
    guard: SpinMutexGuard<'a, T>,
    #[cfg(all(debug_assertions, not(test)))]
    owner: &'a AtomicU8,
    _no_preempt: NoPreempt,
}

impl<T: ?Sized> Deref for KernelMutexGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> DerefMut for KernelMutexGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(all(debug_assertions, not(test)))]
impl<T: ?Sized> Drop for KernelMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.store(NO_OWNER, Ordering::Relaxed);
    }
}

/// See [`KernelMutex::lock_in`]: releases the lock, in the caller's section,
/// which it borrows (and so is not `Send`).
pub struct KernelMutexSectionGuard<'a, T: ?Sized> {
    guard: SpinMutexGuard<'a, T>,
    #[cfg(all(debug_assertions, not(test)))]
    owner: &'a AtomicU8,
    _section: PhantomData<&'a NoPreempt>,
}

impl<T: ?Sized> Deref for KernelMutexSectionGuard<'_, T> {
    type Target = T;

    fn deref(&self) -> &T {
        &self.guard
    }
}

impl<T: ?Sized> DerefMut for KernelMutexSectionGuard<'_, T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.guard
    }
}

#[cfg(all(debug_assertions, not(test)))]
impl<T: ?Sized> Drop for KernelMutexSectionGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.store(NO_OWNER, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::Sections;

    #[test]
    fn sections_enable_interrupts_only_as_the_last_ends_in_any_order() {
        let mut sections = Sections::default();
        sections.begin(true);
        sections.begin(false);
        assert!(!sections.end(), "the first ended, the second lives");
        assert!(sections.end(), "the last ended");
        sections.begin(true);
        sections.begin(false);
        assert!(!sections.end());
        assert!(sections.end(), "in order too");
    }

    #[test]
    fn sections_begun_with_interrupts_disabled_never_enable_them() {
        let mut sections = Sections::default();
        sections.begin(false);
        sections.begin(true);
        assert!(!sections.end());
        assert!(!sections.end());
    }
}
