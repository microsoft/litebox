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

use core::marker::PhantomData;
use core::ops::{Deref, DerefMut};
#[cfg(debug_assertions)]
use core::sync::atomic::{AtomicU8, Ordering};
use spin::mutex::{SpinMutex, SpinMutexGuard};

/// Interrupts disabled, so that the calling code is neither interrupted nor
/// preempted until this drops, which enables them again only if they were:
/// one taken meanwhile stays pending until then. Keeps no other state, so it
/// nests, and is valid anywhere, also as a CPU starts, before its per-CPU
/// variables are installed.
#[must_use = "interrupts are enabled again as it drops"]
pub struct NoPreempt {
    /// Whether interrupts were enabled.
    enabled: bool,
    /// Not `Send`: it restores the state of the code that took it.
    _code: PhantomData<*const ()>,
}

impl NoPreempt {
    pub fn new() -> Self {
        let enabled = x86_64::instructions::interrupts::are_enabled();
        x86_64::instructions::interrupts::disable();
        Self {
            enabled,
            _code: PhantomData,
        }
    }
}

impl Default for NoPreempt {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoPreempt {
    fn drop(&mut self) {
        if self.enabled {
            x86_64::instructions::interrupts::enable();
        }
    }
}

/// Debug builds: asserts that interrupts are disabled, as for every use of
/// a lock that code running with them enabled shares with the kernel. Not in
/// host tests, which run with them enabled.
#[track_caller]
pub(crate) fn debug_assert_disabled() {
    #[cfg(not(test))]
    debug_assert!(
        !x86_64::instructions::interrupts::are_enabled(),
        "a kernel-grade lock taken with interrupts enabled"
    );
}

/// A spin lock that kernel code shares with code that may run with interrupts
/// enabled (see the [module](self) docs): taken with them disabled, which its
/// guard keeps until it drops. Debug builds check that no CPU takes one it
/// holds (it would spin forever), which needs the CPU's per-CPU variables.
pub struct KernelMutex<T: ?Sized> {
    /// Debug builds: the index of the CPU holding it, or [`NO_OWNER`].
    #[cfg(debug_assertions)]
    owner: AtomicU8,
    inner: SpinMutex<T>,
}

/// [`KernelMutex::owner`]: no CPU's.
#[cfg(debug_assertions)]
const NO_OWNER: u8 = u8::MAX;

impl<T> KernelMutex<T> {
    pub const fn new(value: T) -> Self {
        Self {
            #[cfg(debug_assertions)]
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
        let no_preempt = NoPreempt::new();
        #[cfg(debug_assertions)]
        let cpu = {
            let cpu = u8::try_from(crate::cpu::current().index()).expect("CPU indices fit a byte");
            assert_ne!(
                self.owner.load(Ordering::Relaxed),
                cpu,
                "a CPU takes a kernel lock it holds"
            );
            cpu
        };
        let guard = self.inner.lock();
        #[cfg(debug_assertions)]
        self.owner.store(cpu, Ordering::Relaxed);
        KernelMutexGuard {
            guard,
            #[cfg(debug_assertions)]
            owner: &self.owner,
            _no_preempt: no_preempt,
        }
    }
}

/// See [`KernelMutex::lock`]: releases the lock, then restores interrupts.
pub struct KernelMutexGuard<'a, T: ?Sized> {
    // Dropped in this order.
    guard: SpinMutexGuard<'a, T>,
    #[cfg(debug_assertions)]
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

#[cfg(debug_assertions)]
impl<T: ?Sized> Drop for KernelMutexGuard<'_, T> {
    fn drop(&mut self) {
        self.owner.store(NO_OWNER, Ordering::Relaxed);
    }
}
