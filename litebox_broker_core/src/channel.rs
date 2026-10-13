// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Bounded one-way channels.
//!
//! A channel carries data from writers to one reader behind its own lock, so
//! channels between different objects never contend. It counts the queued
//! data in bytes against a capacity, and records the writers that found it
//! full so they can retry once it changes. Writers are woken only after
//! every lock is released, since a woken writer inspects channels again.

use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use spin::{Mutex, MutexGuard};

use crate::{BrokerError, Result};

/// A writer that can wait for a channel to change.
pub(crate) trait Waiter: Send + Sync {
    /// Lets the writer retry after the channel it waited on changed.
    fn wake(self: Arc<Self>);
}

/// A bounded queue of data passing from writers of type `W` to one reader.
pub(crate) struct Channel<Q, W> {
    state: Mutex<ChannelState<Q, W>>,
}

impl<Q, W> Channel<Q, W> {
    /// Creates an open channel holding `queue`, which is full once data
    /// counting `capacity` bytes is queued.
    pub(crate) fn new(queue: Q, capacity: usize) -> Self {
        Self {
            state: Mutex::new(ChannelState {
                queue,
                queued: 0,
                capacity,
                shut: false,
                waiters: Vec::new(),
            }),
        }
    }

    pub(crate) fn lock(&self) -> MutexGuard<'_, ChannelState<Q, W>> {
        self.state.lock()
    }
}

/// The state of a [`Channel`], which its lock guards.
pub(crate) struct ChannelState<Q, W> {
    /// The queued data.
    pub(crate) queue: Q,
    /// Bytes the queued data counts against the capacity.
    queued: usize,
    capacity: usize,
    shut: bool,
    /// Writers to wake once the channel changes.
    waiters: Vec<Weak<W>>,
}

impl<Q, W> ChannelState<Q, W> {
    /// Returns the bytes the queued data counts against the capacity.
    pub(crate) fn queued(&self) -> usize {
        self.queued
    }

    /// Returns how many more bytes fit before the channel is full.
    pub(crate) fn room(&self) -> usize {
        self.capacity.saturating_sub(self.queued)
    }

    /// Records that data counting `bytes` joined the queue.
    pub(crate) fn add(&mut self, bytes: usize) {
        self.queued = self
            .queued
            .checked_add(bytes)
            .expect("a channel's count must fit its queued data");
    }

    /// Records that data counting `bytes` left the queue.
    pub(crate) fn remove(&mut self, bytes: usize) {
        self.queued = self
            .queued
            .checked_sub(bytes)
            .expect("a channel's count must cover its dequeued data");
    }

    /// Returns whether data stopped flowing.
    pub(crate) fn is_shut(&self) -> bool {
        self.shut
    }

    /// Stops data from flowing: writers fail, and the reader reaches the end
    /// of the data once the queue drains.
    pub(crate) fn shut(&mut self) {
        self.shut = true;
    }

    /// Makes `waiter` wait for the channel to change.
    pub(crate) fn wait(&mut self, waiter: &Arc<W>) -> Result<()> {
        // Pruning dropped writers bounds the list by the live ones.
        self.waiters.retain(|waiter| waiter.strong_count() != 0);
        if self
            .waiters
            .iter()
            .any(|waiting| core::ptr::eq(waiting.as_ptr(), Arc::as_ptr(waiter)))
        {
            return Ok(());
        }
        self.waiters
            .try_reserve(1)
            .map_err(|_| BrokerError::OutOfMemory)?;
        self.waiters.push(Arc::downgrade(waiter));
        Ok(())
    }

    /// Takes the waiting writers, to wake once every lock is released.
    ///
    /// Callers take them after any change that may let a writer proceed:
    /// draining the queue, shutting the channel, or changing which writers it
    /// accepts.
    pub(crate) fn wake(&mut self) -> Wakeups<W> {
        Wakeups(core::mem::take(&mut self.waiters))
    }
}

/// Writers to wake once every lock is released.
#[must_use = "waiting writers must be woken"]
pub(crate) struct Wakeups<W>(Vec<Weak<W>>);

impl<W> Default for Wakeups<W> {
    fn default() -> Self {
        Self(Vec::new())
    }
}

impl<W: Waiter> Wakeups<W> {
    pub(crate) fn wake(self) {
        for waiter in self.0 {
            if let Some(waiter) = waiter.upgrade() {
                waiter.wake();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::*;

    #[derive(Default)]
    struct Counter(AtomicUsize);

    impl Waiter for Counter {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }

    #[test]
    fn room_follows_the_queued_count() {
        let channel = Channel::<(), Counter>::new((), 10);
        let mut state = channel.lock();
        assert_eq!(state.room(), 10);
        state.add(12);
        assert_eq!((state.queued(), state.room()), (12, 0));
        state.remove(5);
        assert_eq!((state.queued(), state.room()), (7, 3));
        assert!(!state.is_shut());
        state.shut();
        assert!(state.is_shut());
    }

    #[test]
    fn waiters_are_woken_once_and_only_while_alive() {
        let channel = Channel::<(), Counter>::new((), 1);
        let kept = Arc::new(Counter::default());
        let dropped = Arc::new(Counter::default());
        {
            let mut state = channel.lock();
            state.wait(&kept).unwrap();
            state.wait(&kept).unwrap();
            state.wait(&dropped).unwrap();
        }
        drop(dropped);
        let wakeups = channel.lock().wake();
        wakeups.wake();
        assert_eq!(kept.0.load(Ordering::Relaxed), 1);
        let wakeups = channel.lock().wake();
        wakeups.wake();
        assert_eq!(kept.0.load(Ordering::Relaxed), 1);
    }
}
