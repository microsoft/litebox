// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Test-only instrumentation for the futex wake-path store-buffering stress test.
//!
//! This module exposes a small rendezvous protocol that a stress harness uses to align
//! a waiter and a waker at the exact instant of the two conflicting stores in the futex
//! wake path (the waiter's `WAITING` store in [`WaitContext::start_wait`] and the waker's
//! relaxed `done` store in [`FutexManager::wake`]), and to observe whether each side read
//! the other's stale value.
//!
//! It is compiled only under `cfg(test)` (for the in-crate mock-platform test) or the
//! `futex_ordering_stress` feature (so a dependent crate can drive the same protocol over
//! a real platform). It must never be enabled in production builds: the hooks add a
//! rendezvous barrier inside the live wait/wake paths.
//!
//! [`WaitContext::start_wait`]: crate::event::wait
//! [`FutexManager::wake`]: crate::sync::futex::FutexManager::wake

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

/// The number of participants (waiter + waker) that must park before the harness releases them.
const PARTICIPANTS: u32 = 2;

/// Sentinel meaning "not yet recorded this round".
const UNSET: u32 = u32::MAX;

static ACTIVE: AtomicBool = AtomicBool::new(false);
static PARKED: AtomicU32 = AtomicU32::new(0);
static RELEASE: AtomicBool = AtomicBool::new(false);
static WAITER_REGISTERED: AtomicBool = AtomicBool::new(false);
static WAITER_DONE: AtomicU32 = AtomicU32::new(UNSET);
static WAKER_RESULT: AtomicU32 = AtomicU32::new(UNSET);

/// Enables the instrumentation hooks. Call once before a stress run.
pub fn activate() {
    ACTIVE.store(true, Ordering::Relaxed);
}

/// Disables the instrumentation hooks. Call once after a stress run.
pub fn deactivate() {
    ACTIVE.store(false, Ordering::Relaxed);
}

/// Resets all per-round observation state. Call at the top of each iteration before
/// releasing the two threads.
pub fn begin_round() {
    PARKED.store(0, Ordering::Relaxed);
    RELEASE.store(false, Ordering::Relaxed);
    WAITER_REGISTERED.store(false, Ordering::Relaxed);
    WAITER_DONE.store(UNSET, Ordering::Relaxed);
    WAKER_RESULT.store(UNSET, Ordering::Relaxed);
}

/// Returns whether the waiter has inserted its entry (so the waker's `wake` will select it).
#[must_use]
pub fn waiter_is_registered() -> bool {
    WAITER_REGISTERED.load(Ordering::Acquire)
}

/// Spins until both the waiter and the waker have parked at the rendezvous.
pub fn wait_until_parked() {
    while PARKED.load(Ordering::Acquire) != PARTICIPANTS {
        core::hint::spin_loop();
    }
}

/// Releases the parked waiter and waker together, so their two stores race.
pub fn release() {
    RELEASE.store(true, Ordering::Release);
}

/// Returns whether this round observed the both-old outcome: the waiter's first `done`
/// load read `false` and the waker's `fetch_update` read `RUNNING_IN_HOST` (encoded 0).
#[must_use]
pub fn observed_both_old() -> bool {
    WAITER_DONE.load(Ordering::Relaxed) == 0 && WAKER_RESULT.load(Ordering::Relaxed) == 0
}

/// Hook: the waiter has inserted its entry but has not yet parked.
pub(crate) fn waiter_registered() {
    if ACTIVE.load(Ordering::Relaxed) {
        WAITER_REGISTERED.store(true, Ordering::Release);
    }
}

/// Hook: called immediately before the waiter's `WAITING` store.
pub(crate) fn waiter_rendezvous() {
    if ACTIVE.load(Ordering::Relaxed) {
        rendezvous();
    }
}

/// Hook: called immediately before the waker's relaxed `done` store.
pub(crate) fn waker_rendezvous() {
    if ACTIVE.load(Ordering::Relaxed) {
        rendezvous();
    }
}

/// Hook: records the value of the waiter's first `done` load (first write wins).
pub(crate) fn record_waiter_done(done: bool) {
    if ACTIVE.load(Ordering::Relaxed) {
        let _ = WAITER_DONE.compare_exchange(
            UNSET,
            u32::from(done),
            Ordering::Relaxed,
            Ordering::Relaxed,
        );
    }
}

/// Hook: records the encoded result of the waker's `fetch_update`. `Ok` results set the
/// high bit so a failed `Err(RUNNING_IN_HOST)` (encoded 0) is distinguishable.
pub(crate) fn record_waker_result(result: Result<u32, u32>) {
    if ACTIVE.load(Ordering::Relaxed) {
        let encoded = match result {
            Ok(state) => state | (1 << 31),
            Err(state) => state,
        };
        WAKER_RESULT.store(encoded, Ordering::Relaxed);
    }
}

fn rendezvous() {
    PARKED.fetch_add(1, Ordering::Release);
    while !RELEASE.load(Ordering::Acquire) {
        core::hint::spin_loop();
    }
}
