// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Host tests of wait queues' waiters ([`Waiters`]).

extern crate std;

use super::{Waiters, Wake};
use alloc::boxed::Box;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicBool, Ordering::SeqCst};

/// A waiter whose clears check that `queue`'s lock is held.
struct TestWaker {
    woken: AtomicBool,
    queue: Option<&'static Waiters<TestWaker>>,
}

impl TestWaker {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            woken: AtomicBool::new(false),
            queue: None,
        })
    }

    fn is_woken(&self) -> bool {
        self.woken.load(SeqCst)
    }
}

impl Wake for TestWaker {
    fn clear(&self) {
        if let Some(queue) = self.queue {
            assert!(
                queue.queue.is_locked(),
                "a waiter's wakes are cleared under the lock"
            );
        }
        self.woken.store(false, SeqCst);
    }

    fn wake(&self) {
        self.woken.store(true, SeqCst);
    }
}

#[test]
fn wakes_go_to_the_oldest_waiters_first() {
    let waiters = Waiters::new();
    let [a, b, c] = [TestWaker::new(), TestWaker::new(), TestWaker::new()];
    let _registrations = [&a, &b, &c].map(|waiter| waiters.register(waiter.clone()));
    assert_eq!(waiters.wake(0), 0);
    assert_eq!(waiters.wake(1), 1);
    assert!(a.is_woken() && !b.is_woken() && !c.is_woken());
    assert_eq!(waiters.wake(5), 2);
    assert!(b.is_woken() && c.is_woken());
    assert_eq!(waiters.wake(1), 0, "a wake unregisters");
}

#[test]
fn a_dropped_registration_is_not_woken() {
    let waiters = Waiters::new();
    let (a, b) = (TestWaker::new(), TestWaker::new());
    let registered = waiters.register(a.clone());
    let _registered = waiters.register(b.clone());
    drop(registered);
    assert_eq!(waiters.wake(1), 1);
    assert!(!a.is_woken() && b.is_woken());
}

#[test]
fn a_wake_between_registration_and_sleep_is_kept() {
    let waiters = Waiters::new();
    let a = TestWaker::new();
    let registered = waiters.register(a.clone());
    assert_eq!(waiters.wake(1), 1);
    assert!(registered.waiter().is_woken());
    drop(registered);
    assert_eq!(waiters.wake(1), 0);
}

#[test]
fn registering_forgets_earlier_wakes() {
    let waiters = Waiters::new();
    let a = TestWaker::new();
    drop(waiters.register(a.clone()));
    a.wake();
    let registered = waiters.register(a.clone());
    assert!(!registered.waiter().is_woken());
    assert_eq!(waiters.wake(1), 1);
    assert!(registered.waiter().is_woken());
}

#[test]
fn wakes_are_cleared_under_the_queues_lock() {
    let waiters: &'static Waiters<TestWaker> = Box::leak(Box::new(Waiters::new()));
    let a = Arc::new(TestWaker {
        woken: AtomicBool::new(true),
        queue: Some(waiters),
    });
    let registered = waiters.register(a.clone());
    assert!(!a.is_woken());
    drop(registered);
}
