// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Loom models for platform synchronization primitives.
//!
//! These types are intended for tests in this crate and dependent crates. They
//! model platform behavior with Loom primitives, but they are not production
//! platform implementations.

use core::sync::atomic::Ordering;

use alloc::collections::VecDeque;
use alloc::vec::Vec;
use loom::sync::Mutex;
pub use loom::sync::{Arc, atomic};
use loom::thread;

use super::{
    ImmediatelyWokenUp, Instant, RawAtomicU32, RawMutex, RawMutexProvider, RawPointerProvider,
    SystemTime, TimeProvider, UnblockedOrTimedOut,
};

/// A Loom model of a futex word and its wait queue.
///
/// `block` models `FUTEX_WAIT`: while holding the internal queue lock, it checks
/// whether the word still equals the expected value and only then parks on the
/// condition variable. `wake_many` holds the same queue lock while selecting and
/// notifying waiters, so a wake cannot be lost between the value check and the
/// wait operation.
pub struct LoomFutex {
    word: RawAtomicU32,
    queue: Mutex<WaitQueue>,
}

#[derive(Default)]
struct WaitQueue {
    waiters: VecDeque<Arc<Waiter>>,
}

struct Waiter {
    thread: thread::Thread,
    woken: atomic::AtomicBool,
}

impl LoomFutex {
    /// Creates a new futex model with the given initial word value.
    pub fn new(value: u32) -> Self {
        Self {
            word: atomic::AtomicU32::new(value),
            queue: Mutex::new(WaitQueue::default()),
        }
    }

    /// Returns the modeled futex word.
    pub fn word(&self) -> &atomic::AtomicU32 {
        &self.word
    }

    /// Wakes up to `n` waiters blocked on this futex.
    ///
    /// The returned value is the number of waiters selected for wakeup. This
    /// mirrors futex semantics: selected waiters are no longer eligible for a
    /// second wake, even if they have not yet resumed execution.
    ///
    /// # Panics
    ///
    /// Panics if Loom reports that the modeled wait-queue mutex has been
    /// poisoned.
    pub fn wake_many(&self, n: usize) -> usize {
        let mut queue = self.queue.lock().unwrap();
        let to_wake = queue.waiters.len().min(n);
        let waiters: Vec<_> = (0..to_wake)
            .filter_map(|_| queue.waiters.pop_front())
            .collect();
        drop(queue);

        for waiter in waiters {
            waiter.woken.store(true, Ordering::Release);
            waiter.thread.unpark();
        }

        to_wake
    }

    /// Wakes one waiter blocked on this futex.
    pub fn wake_one(&self) -> bool {
        self.wake_many(1) > 0
    }

    /// Wakes all currently eligible waiters blocked on this futex.
    pub fn wake_all(&self) -> usize {
        self.wake_many(usize::MAX)
    }

    /// Blocks if the futex word is still equal to `expected`.
    ///
    /// This returns after a wake operation selects this waiter. A wake does not
    /// imply that the futex word has changed; callers must re-check their own
    /// synchronization state, just as they would around a real futex wait.
    ///
    /// # Panics
    ///
    /// Panics if Loom reports that the modeled wait-queue mutex or condition
    /// variable has been poisoned.
    pub fn block(&self, expected: u32) -> Result<(), ImmediatelyWokenUp> {
        let waiter = Arc::new(Waiter {
            thread: thread::current(),
            woken: atomic::AtomicBool::new(false),
        });

        let mut queue = self.queue.lock().unwrap();
        let value = self.word.load(Ordering::SeqCst);
        if value != expected {
            return Err(ImmediatelyWokenUp);
        }
        queue.waiters.push_back(Arc::clone(&waiter));
        drop(queue);

        while !waiter.woken.load(Ordering::Acquire) {
            thread::park();
        }
        Ok(())
    }

    /// Blocks like [`Self::block`].
    ///
    /// Loom's condition variable does not model timeouts, so this returns
    /// `Unblocked` after a modeled wake and never produces `TimedOut`.
    ///
    /// # Panics
    ///
    /// Panics under the same conditions as [`Self::block`].
    pub fn block_or_timeout(
        &self,
        expected: u32,
        _timeout: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.block(expected)
            .map(|()| UnblockedOrTimedOut::Unblocked)
    }
}

/// A [`RawMutex`] implementation backed by [`LoomFutex`].
pub struct LoomRawMutex {
    futex: LoomFutex,
}

impl LoomRawMutex {
    /// Creates a new Loom raw mutex.
    pub fn new() -> Self {
        Self {
            futex: LoomFutex::new(0),
        }
    }
}

impl Default for LoomRawMutex {
    fn default() -> Self {
        Self::new()
    }
}

impl RawMutex for LoomRawMutex {
    fn new() -> Self {
        LoomRawMutex::new()
    }

    fn underlying_atomic(&self) -> &RawAtomicU32 {
        self.futex.word()
    }

    fn wake_many(&self, n: usize) -> usize {
        self.futex.wake_many(n)
    }

    fn block(&self, val: u32) -> Result<(), ImmediatelyWokenUp> {
        self.futex.block(val)
    }

    fn block_or_timeout(
        &self,
        val: u32,
        timeout: core::time::Duration,
    ) -> Result<UnblockedOrTimedOut, ImmediatelyWokenUp> {
        self.futex.block_or_timeout(val, timeout)
    }
}

/// A minimal platform for Loom tests of raw synchronization primitives.
pub struct LoomPlatform {
    current_time: atomic::AtomicU64,
}

impl LoomPlatform {
    /// Creates a new Loom platform model.
    pub fn new() -> Self {
        Self {
            current_time: atomic::AtomicU64::new(0),
        }
    }
}

impl Default for LoomPlatform {
    fn default() -> Self {
        Self::new()
    }
}

impl RawMutexProvider for LoomPlatform {
    type RawMutex = LoomRawMutex;
}

impl RawPointerProvider for LoomPlatform {
    type RawConstPointer<T: zerocopy::FromBytes> = super::trivial_providers::TransparentConstPtr<T>;
    type RawMutPointer<T: zerocopy::FromBytes + zerocopy::IntoBytes> =
        super::trivial_providers::TransparentMutPtr<T>;
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct LoomInstant {
    time: u64,
}

impl Instant for LoomInstant {
    fn checked_duration_since(&self, earlier: &Self) -> Option<core::time::Duration> {
        if earlier.time <= self.time {
            Some(core::time::Duration::from_millis(self.time - earlier.time))
        } else {
            None
        }
    }

    fn checked_add(&self, duration: core::time::Duration) -> Option<Self> {
        let duration_millis: u64 = duration.as_millis().try_into().ok()?;
        Some(Self {
            time: self.time.checked_add(duration_millis)?,
        })
    }
}

pub struct LoomSystemTime {
    time: u64,
}

impl SystemTime for LoomSystemTime {
    const UNIX_EPOCH: Self = Self { time: 0 };

    fn duration_since(&self, earlier: &Self) -> Result<core::time::Duration, core::time::Duration> {
        match self.time.cmp(&earlier.time) {
            core::cmp::Ordering::Less => {
                Err(core::time::Duration::from_millis(earlier.time - self.time))
            }
            core::cmp::Ordering::Equal => Ok(core::time::Duration::from_millis(0)),
            core::cmp::Ordering::Greater => {
                Ok(core::time::Duration::from_millis(self.time - earlier.time))
            }
        }
    }
}

impl TimeProvider for LoomPlatform {
    type Instant = LoomInstant;
    type SystemTime = LoomSystemTime;

    fn now(&self) -> Self::Instant {
        LoomInstant {
            time: self.current_time.fetch_add(1, Ordering::SeqCst),
        }
    }

    fn current_time(&self) -> Self::SystemTime {
        LoomSystemTime {
            time: self.current_time.load(Ordering::SeqCst),
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::sync::atomic::Ordering;

    use super::{Arc, LoomFutex, Waiter, atomic};
    use crate::platform::{ImmediatelyWokenUp, UnblockedOrTimedOut};

    macro_rules! loom_trace {
        ($($arg:tt)*) => {{
            std::eprintln!("[{:?}] {}", loom::thread::current().id(), format_args!($($arg)*));
        }};
    }

    fn waiter() -> Arc<Waiter> {
        Arc::new(Waiter {
            thread: loom::thread::current(),
            woken: atomic::AtomicBool::new(false),
        })
    }

    #[test]
    fn block_returns_immediately_when_word_mismatches() {
        loom::model(|| {
            let futex = LoomFutex::new(1);

            match futex.block(0) {
                Err(ImmediatelyWokenUp) => {}
                Ok(()) => panic!("futex wait should not block when the word already differs"),
            }
        });
    }

    #[test]
    fn block_or_timeout_returns_immediately_when_word_mismatches() {
        loom::model(|| {
            let futex = LoomFutex::new(1);

            match futex.block_or_timeout(0, core::time::Duration::from_secs(1)) {
                Err(ImmediatelyWokenUp) => {}
                Ok(UnblockedOrTimedOut::Unblocked) => {
                    panic!("futex wait should not consume a wake when the word already differs")
                }
                Ok(UnblockedOrTimedOut::TimedOut) => {
                    panic!("LoomFutex does not model timeout expiration")
                }
            }
        });
    }

    #[test]
    fn wake_many_returns_zero_without_waiters() {
        loom::model(|| {
            let futex = LoomFutex::new(0);

            assert_eq!(futex.wake_many(1), 0);
            assert_eq!(futex.wake_all(), 0);
        });
    }

    #[test]
    fn wake_one_does_not_select_the_same_waiter_twice() {
        loom::model(|| {
            let futex = LoomFutex::new(0);
            let waiter = waiter();
            futex
                .queue
                .lock()
                .unwrap()
                .waiters
                .push_back(Arc::clone(&waiter));

            assert!(futex.wake_one());
            assert!(!futex.wake_one());
            assert!(waiter.woken.load(Ordering::Acquire));
            assert!(futex.queue.lock().unwrap().waiters.is_empty());
        });
    }

    #[test]
    fn wake_all_selects_all_eligible_waiters() {
        loom::model(|| {
            let futex = LoomFutex::new(0);
            let waiters = [waiter(), waiter(), waiter()];
            futex
                .queue
                .lock()
                .unwrap()
                .waiters
                .extend(waiters.iter().map(Arc::clone));

            assert_eq!(futex.wake_all(), 3);
            assert!(
                waiters
                    .iter()
                    .all(|waiter| waiter.woken.load(Ordering::Acquire))
            );
            assert!(futex.queue.lock().unwrap().waiters.is_empty());
        });
    }

    #[test]
    fn wait_does_not_miss_wake_between_check_and_park() {
        loom::model(|| {
            let futex = Arc::new(LoomFutex::new(0));

            let waiter = {
                let futex = Arc::clone(&futex);
                loom::thread::spawn(move || {
                    for _ in 0..2 {
                        let _ = futex.block(0);
                    }
                })
            };

            let waker = {
                let futex = Arc::clone(&futex);
                loom::thread::spawn(move || {
                    futex.word().store(1, Ordering::Release);
                    futex.wake_one();
                })
            };

            waiter.join().unwrap();
            waker.join().unwrap();
        });
    }

    #[test]
    fn test_seq_cst_ordering() {
        loom::model(|| {
            let first = Arc::new(loom::sync::atomic::AtomicUsize::new(0));
            let second = Arc::new(loom::sync::atomic::AtomicUsize::new(0));
            let sum = Arc::new(loom::sync::atomic::AtomicUsize::new(0));

            let writer = {
                let first_clone = Arc::clone(&first);
                let second_clone = Arc::clone(&second);
                let sum_clone = Arc::clone(&sum);
                loom::thread::spawn(move || {
                    loom_trace!("writer: first.store(1)");
                    first_clone.store(1, Ordering::SeqCst);
                    // loom does not support SeqCst for load/store: see https://github.com/tokio-rs/loom/issues/180
                    loom::sync::atomic::fence(Ordering::SeqCst);
                    let second = second_clone.load(Ordering::SeqCst);
                    loom_trace!("writer: second.load() = {second}");
                    if second == 1 {
                        loom_trace!("writer: sum.fetch_add(1)");
                        sum_clone.fetch_add(1, Ordering::SeqCst);
                    }
                })
            };

            let reader = {
                let sum_clone = Arc::clone(&sum);
                loom::thread::spawn(move || {
                    loom_trace!("reader: second.store(1)");
                    second.store(1, Ordering::SeqCst);
                    loom::sync::atomic::fence(Ordering::SeqCst);
                    let first = first.load(Ordering::SeqCst);
                    loom_trace!("reader: first.load() = {first}");
                    if first == 1 {
                        loom_trace!("reader: sum.fetch_add(1)");
                        sum_clone.fetch_add(1, Ordering::SeqCst);
                    }
                })
            };

            writer.join().unwrap();
            reader.join().unwrap();

            let sum = sum.load(Ordering::SeqCst);
            loom_trace!("main: sum.load() = {sum}");
            assert!(sum == 1 || sum == 2);
        });
    }

    #[test]
    fn test_fetch_update() {
        loom::model(|| {
            let atomic = Arc::new(loom::sync::atomic::AtomicUsize::new(0));

            let updater = {
                let atomic = Arc::clone(&atomic);
                loom::thread::spawn(move || {
                    let result = atomic.fetch_update(Ordering::Release, Ordering::Acquire, |x| {
                        if x == 0 { Some(2) } else { None }
                    });
                    loom_trace!("updater: fetch_update() = {result:?}");
                })
            };

            let writer = {
                let atomic = Arc::clone(&atomic);
                loom::thread::spawn(move || {
                    // `store` would fail the test while `swap` works.
                    // Might relate to https://github.com/tokio-rs/loom/issues/254
                    // atomic.store(1, Ordering::Relaxed);
                    let val = atomic.swap(1, Ordering::Relaxed);
                    loom_trace!("writer: atomic.swap(1) = {val:?}");
                })
            };

            updater.join().unwrap();
            writer.join().unwrap();

            let val = atomic.load(Ordering::Relaxed);
            loom_trace!("main: atomic.load() = {val:?}");
            assert_eq!(val, 1);
        });
    }

    /// Minimal repro of a loom modeling bug: a thread's `Relaxed` load does
    /// not always observe its own immediately-preceding `Relaxed` store to the
    /// same atomic when another thread's RMW has interleaved between two
    /// earlier same-thread writes.
    ///
    /// Schedule explored by loom:
    /// - T1: store(1, SeqCst); fence(SeqCst);
    /// - T2: compare_exchange(1, 2, Release, Relaxed);
    /// - T1: store(0, Relaxed);
    /// - T1: load(Relaxed);
    ///
    /// See https://github.com/tokio-rs/loom/issues/389 for more detail.
    #[test]
    fn relaxed_load_does_not_observe_own_relaxed_store() {
        loom::model(|| {
            let v = Arc::new(atomic::AtomicU32::new(0));

            let t2 = {
                let v = Arc::clone(&v);
                loom::thread::spawn(move || {
                    loom_trace!("T2: compare_exchange(1, 2)");
                    let old = v.compare_exchange(1, 2, Ordering::Release, Ordering::Relaxed);
                    loom_trace!("T2: compare_exchange returned {old:?}");
                })
            };

            v.store(1, Ordering::SeqCst);
            loom::sync::atomic::fence(Ordering::SeqCst);
            loom::thread::yield_now();

            // See https://github.com/tokio-rs/loom/issues/389
            // v.store(0, Ordering::Relaxed);
            let _ = v.swap(0, Ordering::Relaxed);
            let observed = v.load(Ordering::Relaxed);
            loom_trace!("T1: final load = {observed}");

            t2.join().unwrap();

            assert_eq!(
                observed, 0,
                "T1's Relaxed load must observe its own preceding Relaxed store \
                 of 0 (CoWR coherence); loom #180-style modeling artifact"
            );
        });
    }
}
