// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host tests of a kernel thread's spin for a lock ([`spin_for`]), alone and
//! through `litebox_platform::sync`'s locks, against a scripted holder.

extern crate std;

use super::{Instant, SpinEnd, spin_for};
use core::cell::{Cell, RefCell};
use core::sync::atomic::{AtomicU32, Ordering};
use core::time::Duration;
use litebox_platform::sync::{
    ImmediatelyWokenUp, Mutex, RawMutex, RawMutexProvider, RwLock, UnblockedOrTimedOut,
};
use std::vec::Vec;

const BUDGET: Duration = Duration::from_micros(250);
const STEP: Duration = Duration::from_micros(10);
/// `litebox_platform::sync`'s `RwLock` word, write-locked with no waiters.
const WRITE_LOCKED: u32 = (1 << 30) - 1;

struct State {
    clock: Cell<Duration>,
    /// At each of the waiter's relaxes, `Some(word)` stores `word`.
    script: RefCell<Vec<Option<u32>>>,
    waits: RefCell<Vec<Duration>>,
}

std::thread_local! {
    static STATE: State = const {
        State {
            clock: Cell::new(Duration::ZERO),
            script: RefCell::new(Vec::new()),
            waits: RefCell::new(Vec::new()),
        }
    };
}

fn clock() -> Duration {
    STATE.with(|state| state.clock.get())
}

fn since(start: Duration) -> Duration {
    clock().checked_sub(start).expect("the clock only advances")
}

fn now() -> Instant {
    Instant::from_nanos(u64::try_from(clock().as_nanos()).expect("a short test clock"))
}

fn tick() {
    STATE.with(|state| state.clock.set(state.clock.get() + STEP));
}

/// As `VmKernel`'s locks, with the scripted holder and clock.
struct Scripted;

impl RawMutexProvider for Scripted {
    type RawMutex = ScriptedRaw;
}

struct ScriptedRaw(AtomicU32);

impl RawMutex for ScriptedRaw {
    const INIT: Self = Self(AtomicU32::new(0));

    fn underlying_atomic(&self) -> &AtomicU32 {
        &self.0
    }

    fn wake_many(&self, _count: usize) -> usize {
        0
    }

    fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        let start = clock();
        let relax = || {
            tick();
            let step = STATE.with(|state| {
                let mut script = state.script.borrow_mut();
                if script.is_empty() {
                    None
                } else {
                    script.remove(0)
                }
            });
            if let Some(word) = step {
                self.0.store(word, Ordering::Relaxed);
            }
        };
        let end = spin_for(&self.0, expected, BUDGET, now, relax, || false);
        STATE.with(|state| state.waits.borrow_mut().push(since(start)));
        match end {
            SpinEnd::Differed => Err(ImmediatelyWokenUp),
            SpinEnd::Changed => Ok(()),
            SpinEnd::Expired => panic!("the script left the word unchanged for a whole budget"),
        }
    }

    fn block_or_timeout(
        &self,
        _expected: u32,
        _timeout: Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        unreachable!("no timeouts")
    }
}

/// At each wait's `relaxes`-th relax, the holder releases the lock and
/// another takes it (`taken`), `losses` times; then it stays free.
fn script_losses(losses: usize, relaxes: usize, taken: u32) {
    let mut script = Vec::new();
    for loss in 0..=losses {
        script.extend(core::iter::repeat_n(None, relaxes - 1));
        script.push(Some(if loss < losses { taken } else { 0 }));
    }
    STATE.with(|state| *state.script.borrow_mut() = script);
}

fn waits() -> Vec<Duration> {
    STATE.with(|state| state.waits.borrow().clone())
}

#[test]
fn a_mutex_waiter_that_keeps_losing_spins_a_budget_per_wait() {
    let lock: Mutex<Scripted, ()> = Mutex::new(());
    core::mem::forget(lock.lock());
    script_losses(5, 24, 1);
    drop(lock.lock());
    let waits = waits();
    assert_eq!(waits.len(), 6, "{waits:?}");
    assert!(waits.iter().all(|&spun| spun <= BUDGET), "{waits:?}");
    assert!(waits.iter().sum::<Duration>() > BUDGET * 5 / 2, "{waits:?}");
}

#[test]
fn a_reader_that_keeps_losing_to_writers_spins_a_budget_per_wait() {
    let lock: RwLock<Scripted, ()> = RwLock::new(());
    core::mem::forget(lock.write());
    script_losses(5, 24, WRITE_LOCKED);
    drop(lock.read());
    let waits = waits();
    assert_eq!(waits.len(), 6, "{waits:?}");
    assert!(waits.iter().all(|&spun| spun <= BUDGET), "{waits:?}");
}

#[test]
fn a_wait_with_no_change_expires_at_its_budget_or_once_stopped() {
    let word = AtomicU32::new(2);
    let start = clock();
    assert_eq!(
        spin_for(&word, 2, BUDGET, now, tick, || false),
        SpinEnd::Expired
    );
    let spun = since(start);
    assert!((BUDGET..BUDGET + STEP).contains(&spun), "{spun:?}");
    let start = clock();
    let mut looks = 0;
    let stop = || {
        looks += 1;
        looks == 3
    };
    assert_eq!(
        spin_for(&word, 2, BUDGET, now, tick, stop),
        SpinEnd::Expired
    );
    assert_eq!(since(start), 3 * STEP, "stopped at its third look");
    let start = clock();
    assert_eq!(
        spin_for(&word, 1, BUDGET, now, tick, || panic!("no spin")),
        SpinEnd::Differed
    );
    assert_eq!(clock(), start);
}
