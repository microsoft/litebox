// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

use super::*;
use litebox_platform::sync::{Mutex, RwLock};
use std::sync::{
    Arc, Barrier,
    mpsc::{self, Receiver, RecvTimeoutError},
};
use std::thread::{self, JoinHandle};
use std::time::Instant;

type MacosMutex<T> = Mutex<MacosSyncPrimitivesProvider, T>;
type MacosRwLock<T> = RwLock<MacosSyncPrimitivesProvider, T>;
type WaitResult = Result<UnblockedOrTimedOut, ImmediatelyWokenUp>;
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

struct Waiters {
    raw: Arc<MacosRawMutex>,
    threads: Vec<JoinHandle<()>>,
}

impl Waiters {
    fn start(count: usize, timeout: Option<Duration>) -> (Self, Receiver<WaitResult>) {
        let raw = Arc::new(MacosRawMutex::INIT);
        let (started, ready) = mpsc::channel();
        let (completed, completion) = mpsc::channel();
        let threads = (0..count)
            .map(|_| {
                let raw = Arc::clone(&raw);
                let started = started.clone();
                let completed = completed.clone();
                thread::spawn(move || {
                    started.send(()).unwrap();
                    let result = match timeout {
                        Some(timeout) => raw.block_or_timeout(0, timeout),
                        None => raw.block(0).map(|()| UnblockedOrTimedOut::Unblocked),
                    };
                    let _ = completed.send(result);
                })
            })
            .collect();
        let waiters = Self { raw, threads };
        for _ in 0..count {
            ready.recv_timeout(TEST_TIMEOUT).unwrap();
        }
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));
        (waiters, completion)
    }

    fn wake_exactly(&self, count: usize) {
        let deadline = Instant::now() + TEST_TIMEOUT;
        let mut woken = 0;
        while woken < count {
            // A ready thread may not have entered the kernel yet. Retry only
            // for waiters the native API says have not actually been woken.
            woken += self.raw.wake_many(count - woken);
            assert!(woken <= count, "woke more waiters than requested");
            assert!(
                Instant::now() < deadline,
                "wake did not find blocked waiters"
            );
            thread::yield_now();
        }
    }
}

impl Drop for Waiters {
    fn drop(&mut self) {
        // Release even an indefinite waiter when an assertion fails or the
        // wake_many implementation regresses. Late waiters see the changed word.
        self.raw.state.store(1, Ordering::Release);
        // SAFETY: raw remains live through all joins, and its word and flags
        // match the waits. Bypass the method under test for failure cleanup.
        unsafe {
            let _ = os_sync_wake_by_address_all(
                self.raw.address(),
                size_of::<u32>(),
                OsSyncFlags::empty(),
            );
        }
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

#[test]
fn contended_block_is_released_by_wake() {
    let (waiters, completion) = Waiters::start(1, None);
    waiters.wake_exactly(1);
    assert_eq!(
        completion.recv_timeout(TEST_TIMEOUT).unwrap(),
        Ok(UnblockedOrTimedOut::Unblocked)
    );
    assert_eq!(waiters.raw.state.load(Ordering::Relaxed), 0);
}

#[test]
fn contended_timed_block_is_released_before_timeout() {
    let (waiters, completion) = Waiters::start(1, Some(TEST_TIMEOUT));
    waiters.wake_exactly(1);
    assert_eq!(
        completion.recv_timeout(TEST_TIMEOUT).unwrap(),
        Ok(UnblockedOrTimedOut::Unblocked)
    );
}

#[test]
fn multi_day_timed_block_can_be_woken() {
    let (waiters, completion) = Waiters::start(1, Some(Duration::from_hours(25)));
    waiters.wake_exactly(1);
    assert_eq!(
        completion.recv_timeout(TEST_TIMEOUT).unwrap(),
        Ok(UnblockedOrTimedOut::Unblocked)
    );
}

#[test]
fn wake_many_is_bounded_and_wake_all_releases_remaining_waiters() {
    let (waiters, completion) = Waiters::start(8, Some(TEST_TIMEOUT));
    for count in [1, 2] {
        waiters.wake_exactly(count);
        for _ in 0..count {
            assert_eq!(
                completion.recv_timeout(TEST_TIMEOUT).unwrap(),
                Ok(UnblockedOrTimedOut::Unblocked)
            );
        }
        assert!(matches!(
            completion.recv_timeout(Duration::from_millis(20)),
            Err(RecvTimeoutError::Timeout)
        ));
    }
    waiters.raw.wake_all();
    for _ in 0..5 {
        assert_eq!(
            completion.recv_timeout(TEST_TIMEOUT).unwrap(),
            Ok(UnblockedOrTimedOut::Unblocked)
        );
    }
    assert_eq!(waiters.raw.state.load(Ordering::Relaxed), 0);
}

#[test]
fn wakes_without_waiters_are_harmless() {
    let raw = MacosRawMutex::INIT;
    assert_eq!(raw.wake_many(1), 0);
    assert_eq!(raw.wake_many(4), 0);
    assert_eq!(raw.wake_all(), 0);
    assert_eq!(raw.wake_many(usize::MAX), 0);
}

#[test]
#[should_panic(expected = "wake count must be nonzero")]
fn zero_wake_count_is_rejected() {
    let raw = MacosRawMutex::INIT;
    raw.wake_many(0);
}

#[test]
fn changed_value_does_not_block_and_zero_timeout_expires() {
    let raw = MacosRawMutex::INIT;
    assert_eq!(raw.block(1), Err(ImmediatelyWokenUp));
    for timeout in [Duration::ZERO, Duration::MAX] {
        assert_eq!(raw.block_or_timeout(1, timeout), Err(ImmediatelyWokenUp));
    }
    assert_eq!(
        raw.block_or_timeout(0, Duration::ZERO),
        Ok(UnblockedOrTimedOut::TimedOut)
    );
}

#[test]
fn nonzero_timeout_expires_while_value_is_unchanged() {
    let raw = MacosRawMutex::INIT;
    let timeout = Duration::from_millis(20);
    let deadline = Instant::now() + TEST_TIMEOUT;
    loop {
        let start = Instant::now();
        match raw.block_or_timeout(0, timeout).unwrap() {
            UnblockedOrTimedOut::TimedOut => {
                assert!(start.elapsed() >= timeout);
                break;
            }
            UnblockedOrTimedOut::Unblocked => assert!(Instant::now() < deadline),
        }
    }
}

#[test]
fn long_timeout_consumes_all_chunks_before_reporting_timeout() {
    let mut chunks = Vec::new();
    assert_eq!(
        wait_in_chunks(Duration::from_hours(49) + Duration::from_nanos(1), |ns| {
            chunks.push(Duration::from_nanos(ns));
            Ok(UnblockedOrTimedOut::TimedOut)
        }),
        Ok(UnblockedOrTimedOut::TimedOut)
    );
    assert_eq!(
        chunks,
        [
            Duration::from_hours(24),
            Duration::from_hours(24),
            Duration::from_hours(1) + Duration::from_nanos(1)
        ]
    );
}

#[test]
fn changed_value_before_first_chunk_is_immediate() {
    let mut calls = 0;
    assert_eq!(
        wait_in_chunks(Duration::from_hours(49), |_| {
            calls += 1;
            Err(ImmediatelyWokenUp)
        }),
        Err(ImmediatelyWokenUp)
    );
    assert_eq!(calls, 1);
}

#[test]
fn long_timeout_stops_on_wake_or_value_change_between_chunks() {
    for terminal in [Ok(UnblockedOrTimedOut::Unblocked), Err(ImmediatelyWokenUp)] {
        let mut calls = 0;
        assert_eq!(
            wait_in_chunks(Duration::from_hours(49), |_| {
                calls += 1;
                if calls == 1 {
                    Ok(UnblockedOrTimedOut::TimedOut)
                } else {
                    terminal
                }
            }),
            Ok(UnblockedOrTimedOut::Unblocked)
        );
        assert_eq!(calls, 2);
    }
}

#[test]
fn timeout_chunk_conversion_handles_zero_and_maximum_duration() {
    assert_eq!(
        wait_in_chunks(Duration::ZERO, |_| panic!(
            "zero timeout reached native wait"
        )),
        Ok(UnblockedOrTimedOut::TimedOut)
    );
    let mut calls = 0;
    assert_eq!(
        wait_in_chunks(Duration::MAX, |ns| {
            assert_eq!(Duration::from_nanos(ns), Duration::from_hours(24));
            calls += 1;
            Ok(UnblockedOrTimedOut::Unblocked)
        }),
        Ok(UnblockedOrTimedOut::Unblocked)
    );
    assert_eq!(calls, 1);
}

#[test]
fn mutex_serializes_contended_mutation() {
    let value = Arc::new(MacosMutex::new(0));
    let start = Arc::new(Barrier::new(5));
    let (completed, completion) = mpsc::channel();
    let held = value.lock();
    let threads: Vec<_> = (0..4)
        .map(|_| {
            let value = Arc::clone(&value);
            let start = Arc::clone(&start);
            let completed = completed.clone();
            thread::spawn(move || {
                start.wait();
                for _ in 0..1_000 {
                    let mut guard = value.lock();
                    let previous = *guard;
                    thread::yield_now();
                    *guard = previous + 1;
                }
                completed.send(()).unwrap();
            })
        })
        .collect();
    start.wait();
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));
    drop(held);
    for thread in threads {
        completion.recv_timeout(TEST_TIMEOUT).unwrap();
        thread.join().unwrap();
    }
    assert_eq!(*value.lock(), 4_000);
}

#[test]
fn rwlock_allows_shared_reads_and_blocks_a_writer_until_all_readers_release() {
    let value = Arc::new(MacosRwLock::new(0));
    let first = value.read();
    let second = value.read();
    let (started, ready) = mpsc::channel();
    let (completed, completion) = mpsc::channel();
    let writer_value = Arc::clone(&value);
    let writer = thread::spawn(move || {
        started.send(()).unwrap();
        *writer_value.write() = 1;
        completed.send(()).unwrap();
    });
    ready.recv_timeout(TEST_TIMEOUT).unwrap();
    assert_eq!((*first, *second), (0, 0));
    drop(first);
    assert!(matches!(
        completion.recv_timeout(Duration::from_millis(20)),
        Err(RecvTimeoutError::Timeout)
    ));
    drop(second);
    completion.recv_timeout(TEST_TIMEOUT).unwrap();
    writer.join().unwrap();
    assert_eq!(*value.read(), 1);
}

#[test]
fn rwlock_serializes_writers_and_keeps_reader_snapshots_consistent() {
    let value = Arc::new(MacosRwLock::new((0, 0)));
    let start = Arc::new(Barrier::new(7));
    let (completed, completion) = mpsc::channel();
    let threads: Vec<_> = (0..6)
        .map(|id| {
            let value = Arc::clone(&value);
            let start = Arc::clone(&start);
            let completed = completed.clone();
            thread::spawn(move || {
                start.wait();
                for _ in 0..1_000 {
                    if id < 4 {
                        let mut guard = value.write();
                        guard.0 += 1;
                        thread::yield_now();
                        guard.1 = guard.0;
                    } else {
                        let guard = value.read();
                        assert_eq!(guard.0, guard.1);
                        thread::yield_now();
                    }
                }
                completed.send(()).unwrap();
            })
        })
        .collect();
    start.wait();
    for thread in threads {
        completion.recv_timeout(TEST_TIMEOUT).unwrap();
        thread.join().unwrap();
    }
    assert_eq!(*value.read(), (4_000, 4_000));
}
