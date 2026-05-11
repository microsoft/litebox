// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

//! Worker-side facade for a broker-hosted eventfd.
//!
//! Pairs the [`crate::fd_token_client::FdTokenClient`] (handle
//! lifecycle, RPC ops) with the [`crate::notification_ring::NotificationReceiver`]
//! (async state-change events from the broker) into one ergonomic type.
//! Each [`BrokerEventfd`] represents one logical eventfd from the
//! worker's perspective: read/write/subscribe/poll all route to the
//! broker, but the caller doesn't see that.
//!
//! # Architecture
//!
//! ```text
//!  Worker process                                  Broker process
//!  ─────────────────────────────                   ───────────────────────
//!  BrokerEventfd                                    state_registry
//!    ├─ FdTokenClient ─── TCP control sock ──▶      → handle ops
//!    └─ notification reader thread  ◀──── shm ring ←── notifies on state change
//! ```
//!
//! The notification reader thread is owned by a higher-level
//! [`NotificationDispatcher`] which is shared across all
//! `BrokerEventfd` instances in a worker — there's only one
//! notification ring per worker, multiplexed by `subscription_id`.
//!
//! # Phase boundary
//!
//! Phase B-Step7a: worker-side facade + dispatcher. Not yet wired
//! into `litebox_shim_linux::syscalls::eventfd`; doing so requires
//! a Platform-trait indirection because the shim is `no_std` and
//! cannot directly import this `std`-only crate. The integration
//! is Step 7b.

use crate::fd_token_client::{ClientError, FdTokenClient};
#[cfg(test)]
use crate::notification_frame::NotificationFrame;
use crate::notification_ring::NotificationReceiver;
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};

/// Callback invoked when a [`NotificationFrame`] arrives for a
/// particular subscription. Implementations typically wake a local
/// `Pollee` so that `epoll_wait` / `poll` callers return.
pub trait NotificationCallback: Send + Sync {
    fn on_events(&self, events: u32);
}

/// Routes notification frames arriving on the worker's ring to the
/// matching callback by `subscription_id`. Spawn one per worker; share
/// across all `BrokerEventfd` instances.
pub struct NotificationDispatcher {
    callbacks: Arc<Mutex<HashMap<u64, Arc<dyn NotificationCallback>>>>,
    next_id: AtomicU64,
    thread_handle: Mutex<Option<JoinHandle<()>>>,
}

impl NotificationDispatcher {
    /// Creates a dispatcher and starts its reader thread, which
    /// consumes frames from `receiver` and dispatches by id.
    ///
    /// # Panics
    ///
    /// Panics if the OS refuses to spawn the reader thread.
    pub fn start(mut receiver: NotificationReceiver) -> Arc<Self> {
        let callbacks: Arc<Mutex<HashMap<u64, Arc<dyn NotificationCallback>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let dispatcher = Arc::new(Self {
            callbacks: Arc::clone(&callbacks),
            next_id: AtomicU64::new(1),
            thread_handle: Mutex::new(None),
        });
        let handle = thread::Builder::new()
            .name("broker-notification-reader".into())
            .spawn(move || {
                loop {
                    let Ok(frame) = receiver.recv() else {
                        // EOF (broker closed) or hard error — exit.
                        return;
                    };
                    let cb = {
                        let map = callbacks.lock().expect("callbacks mutex poisoned");
                        map.get(&frame.subscription_id).cloned()
                    };
                    if let Some(cb) = cb {
                        cb.on_events(frame.events);
                    }
                    // Otherwise: no callback (subscription removed
                    // concurrent with broker pushing the frame); drop.
                }
            })
            .expect("spawn notification reader");
        *dispatcher.thread_handle.lock().unwrap() = Some(handle);
        dispatcher
    }

    /// Creates a dispatcher with NO reader thread. Subscriptions can
    /// still be registered but broker→worker notifications will never
    /// be delivered (poll/epoll on a broker-backed eventfd will not
    /// wake from a cross-worker write). Synchronous RPC operations
    /// (create/read/write/release/dup) on the corresponding
    /// `FdTokenClient` are unaffected.
    ///
    /// Phase B-Step9 followup: the runner uses this constructor
    /// because spawning a background thread in the parent process
    /// breaks fork-snapshot/restore. A future Step 12 will either
    /// integrate the loop into the runner's event loop or make the
    /// thread fork-safe.
    pub fn start_without_reader_thread() -> Arc<Self> {
        Arc::new(Self {
            callbacks: Arc::new(Mutex::new(HashMap::new())),
            next_id: AtomicU64::new(1),
            thread_handle: Mutex::new(None),
        })
    }

    /// Allocates a fresh `subscription_id` unique to this dispatcher.
    pub fn alloc_subscription_id(&self) -> u64 {
        self.next_id.fetch_add(1, Ordering::Relaxed)
    }

    /// Registers a callback for `subscription_id`. Overwrites any
    /// existing callback at that id; callers must coordinate id
    /// uniqueness via [`Self::alloc_subscription_id`].
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex was poisoned by a prior panic.
    pub fn register_callback(&self, subscription_id: u64, cb: Arc<dyn NotificationCallback>) {
        self.callbacks
            .lock()
            .expect("callbacks mutex poisoned")
            .insert(subscription_id, cb);
    }

    /// Removes the callback for `subscription_id`. No-op if absent.
    ///
    /// # Panics
    ///
    /// Panics if the internal mutex was poisoned by a prior panic.
    pub fn unregister_callback(&self, subscription_id: u64) {
        self.callbacks
            .lock()
            .expect("callbacks mutex poisoned")
            .remove(&subscription_id);
    }
}

/// Worker-side facade for a broker-hosted eventfd. Wraps an
/// `FdTokenClient` and exposes Linux-eventfd-shaped operations.
///
/// Dropping a `BrokerEventfd` does **not** automatically release the
/// underlying broker handle. Callers must explicitly invoke
/// [`Self::close`] when done; this matches Linux `close(2)` semantics
/// where the caller owns the lifecycle.
pub struct BrokerEventfd {
    client: Arc<FdTokenClient>,
    handle_id: u64,
}

impl BrokerEventfd {
    /// Creates a new broker-hosted eventfd via the supplied client.
    /// Equivalent to Linux `eventfd2(initval, flags)` with `flags`
    /// reduced to its semaphore bit.
    pub fn create(
        client: Arc<FdTokenClient>,
        initial: u64,
        semaphore: bool,
    ) -> Result<Self, ClientError> {
        let handle_id = client.create_eventfd(initial, semaphore)?;
        Ok(Self { client, handle_id })
    }

    /// Returns the broker handle id.
    pub fn handle_id(&self) -> u64 {
        self.handle_id
    }

    /// Performs `read(2)` on the eventfd.
    pub fn read(&self) -> Result<u64, ClientError> {
        self.client.read_eventfd(self.handle_id)
    }

    /// Performs `write(2)` on the eventfd.
    pub fn write(&self, value: u64) -> Result<(), ClientError> {
        self.client.write_eventfd(self.handle_id, value)
    }

    /// Registers a subscription with the supplied [`NotificationDispatcher`].
    /// The dispatcher allocates a unique `subscription_id`, registers the
    /// callback, and tells the broker to start pushing events for this
    /// (handle, events_mask). Returns the subscription_id so the caller
    /// can later [`Self::unsubscribe`].
    pub fn subscribe(
        &self,
        dispatcher: &NotificationDispatcher,
        events_mask: u32,
        callback: Arc<dyn NotificationCallback>,
    ) -> Result<u64, ClientError> {
        let subscription_id = dispatcher.alloc_subscription_id();
        dispatcher.register_callback(subscription_id, callback);
        match self
            .client
            .subscribe_eventfd(self.handle_id, subscription_id, events_mask)
        {
            Ok(()) => Ok(subscription_id),
            Err(e) => {
                // Roll back the callback registration on failure.
                dispatcher.unregister_callback(subscription_id);
                Err(e)
            }
        }
    }

    /// Removes a subscription.
    pub fn unsubscribe(
        &self,
        dispatcher: &NotificationDispatcher,
        subscription_id: u64,
    ) -> Result<(), ClientError> {
        dispatcher.unregister_callback(subscription_id);
        self.client.unsubscribe(self.handle_id, subscription_id)
    }

    /// Releases the broker handle. Idempotent in the sense that the
    /// caller is responsible for calling this exactly once.
    pub fn close(self) -> Result<(), ClientError> {
        self.client.release(self.handle_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::notification_frame::{NOTIFY_EVENT_IN, NOTIFY_EVENT_OUT};
    use crate::notification_ring::NotificationSender;
    use crate::shmem_ring::ShmemRingPair;
    use std::sync::Condvar;
    use std::sync::atomic::{AtomicU32, Ordering};

    struct CountingCallback {
        events: AtomicU32,
        count: AtomicU32,
        notifier: Arc<(Mutex<()>, Condvar)>,
    }

    impl CountingCallback {
        fn new() -> Arc<Self> {
            Arc::new(Self {
                events: AtomicU32::new(0),
                count: AtomicU32::new(0),
                notifier: Arc::new((Mutex::new(()), Condvar::new())),
            })
        }
        fn wait_for_count(&self, target: u32, timeout_ms: u64) {
            let (lock, cvar) = &*self.notifier;
            let mut g = lock.lock().unwrap();
            let deadline = std::time::Duration::from_millis(timeout_ms);
            while self.count.load(Ordering::SeqCst) < target {
                let r = cvar.wait_timeout(g, deadline).unwrap();
                g = r.0;
                if r.1.timed_out() {
                    break;
                }
            }
        }
    }

    impl NotificationCallback for CountingCallback {
        fn on_events(&self, events: u32) {
            self.events.fetch_or(events, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
            let (_lock, cvar) = &*self.notifier;
            cvar.notify_all();
        }
    }

    /// Build (broker NotificationSender, worker NotificationReceiver)
    /// for tests that don't go through a real socket.
    fn make_ring_for_test() -> (NotificationSender, NotificationReceiver) {
        let (pair, tx_fd, rx_fd) = ShmemRingPair::create().unwrap();
        let (broker_writer, _broker_reader_unused) = pair.into_parts();
        let (_worker_writer_unused, worker_reader) = ShmemRingPair::open(tx_fd, rx_fd).unwrap();
        (
            NotificationSender::new(broker_writer),
            NotificationReceiver::new(worker_reader),
        )
    }

    #[test]
    fn dispatcher_routes_by_subscription_id() {
        let (mut sender, receiver) = make_ring_for_test();
        let dispatcher = NotificationDispatcher::start(receiver);

        let cb_a = CountingCallback::new();
        let cb_b = CountingCallback::new();
        dispatcher.register_callback(1, Arc::clone(&cb_a) as Arc<dyn NotificationCallback>);
        dispatcher.register_callback(2, Arc::clone(&cb_b) as Arc<dyn NotificationCallback>);

        sender
            .send(NotificationFrame {
                subscription_id: 1,
                events: NOTIFY_EVENT_IN,
            })
            .unwrap();
        sender
            .send(NotificationFrame {
                subscription_id: 2,
                events: NOTIFY_EVENT_OUT,
            })
            .unwrap();
        sender
            .send(NotificationFrame {
                subscription_id: 1,
                events: NOTIFY_EVENT_OUT,
            })
            .unwrap();

        cb_a.wait_for_count(2, 1000);
        cb_b.wait_for_count(1, 1000);
        assert_eq!(cb_a.count.load(Ordering::SeqCst), 2);
        assert_eq!(cb_b.count.load(Ordering::SeqCst), 1);
        assert_eq!(
            cb_a.events.load(Ordering::SeqCst),
            NOTIFY_EVENT_IN | NOTIFY_EVENT_OUT
        );
        assert_eq!(cb_b.events.load(Ordering::SeqCst), NOTIFY_EVENT_OUT);
    }

    #[test]
    fn dispatcher_drops_frames_for_unregistered_ids() {
        let (mut sender, receiver) = make_ring_for_test();
        let dispatcher = NotificationDispatcher::start(receiver);

        let cb_a = CountingCallback::new();
        dispatcher.register_callback(1, Arc::clone(&cb_a) as Arc<dyn NotificationCallback>);

        sender
            .send(NotificationFrame {
                subscription_id: 42, // not registered
                events: NOTIFY_EVENT_IN,
            })
            .unwrap();
        sender
            .send(NotificationFrame {
                subscription_id: 1,
                events: NOTIFY_EVENT_IN,
            })
            .unwrap();

        cb_a.wait_for_count(1, 1000);
        assert_eq!(cb_a.count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn dispatcher_alloc_subscription_id_monotonic() {
        let (_sender, receiver) = make_ring_for_test();
        let dispatcher = NotificationDispatcher::start(receiver);
        let id1 = dispatcher.alloc_subscription_id();
        let id2 = dispatcher.alloc_subscription_id();
        let id3 = dispatcher.alloc_subscription_id();
        assert!(id1 < id2 && id2 < id3);
    }

    #[test]
    fn unregister_stops_dispatch() {
        let (mut sender, receiver) = make_ring_for_test();
        let dispatcher = NotificationDispatcher::start(receiver);

        let cb = CountingCallback::new();
        dispatcher.register_callback(1, Arc::clone(&cb) as Arc<dyn NotificationCallback>);
        dispatcher.unregister_callback(1);

        sender
            .send(NotificationFrame {
                subscription_id: 1,
                events: NOTIFY_EVENT_IN,
            })
            .unwrap();

        // Give the reader a moment to process.
        std::thread::sleep(std::time::Duration::from_millis(50));
        assert_eq!(cb.count.load(Ordering::SeqCst), 0);
    }

    /// Test C: stress the dispatcher with many subscriptions and a
    /// stream of notifications. Verifies the HashMap-based lookup
    /// holds up under load and every frame is delivered to the right
    /// callback.
    #[test]
    fn stress_many_subscriptions_many_frames() {
        use std::vec::Vec;

        const N_SUBS: u64 = 100;
        const N_FRAMES_PER_SUB: u32 = 50;

        let (mut sender, receiver) = make_ring_for_test();
        let dispatcher = NotificationDispatcher::start(receiver);

        // Allocate ids 1..=N_SUBS and register a counting callback
        // for each.
        let mut callbacks: Vec<Arc<CountingCallback>> = Vec::with_capacity(N_SUBS as usize);
        for id in 1..=N_SUBS {
            let cb = CountingCallback::new();
            dispatcher.register_callback(id, Arc::clone(&cb) as Arc<dyn NotificationCallback>);
            callbacks.push(cb);
        }

        // Round-robin fire N_FRAMES_PER_SUB frames per subscription.
        for round in 0..N_FRAMES_PER_SUB {
            for id in 1..=N_SUBS {
                let events = if round % 2 == 0 {
                    NOTIFY_EVENT_IN
                } else {
                    NOTIFY_EVENT_OUT
                };
                sender
                    .send(NotificationFrame {
                        subscription_id: id,
                        events,
                    })
                    .unwrap();
            }
        }

        // Wait for each callback to see its full count, then verify.
        for (i, cb) in callbacks.iter().enumerate() {
            cb.wait_for_count(N_FRAMES_PER_SUB, 5000);
            assert_eq!(
                cb.count.load(Ordering::SeqCst),
                N_FRAMES_PER_SUB,
                "subscription {} received wrong frame count",
                i + 1,
            );
            // Both event bits should have been observed (round-robin alternates).
            let e = cb.events.load(Ordering::SeqCst);
            assert!(
                e & NOTIFY_EVENT_IN != 0 && e & NOTIFY_EVENT_OUT != 0,
                "subscription {} missed an event bit, got 0x{:x}",
                i + 1,
                e,
            );
        }
    }

    /// Concurrent register + unregister + frame-receive. Verifies the
    /// dispatcher's locking doesn't deadlock or drop frames under
    /// reasonable contention.
    #[test]
    fn concurrent_register_unregister_smoke() {
        use std::thread;

        let (mut sender, receiver) = make_ring_for_test();
        let dispatcher = NotificationDispatcher::start(receiver);

        // Background thread: register+unregister callbacks in a loop.
        let dispatcher_for_thread = Arc::clone(&dispatcher);
        let bg = thread::spawn(move || {
            for round in 0..200 {
                let id = 10_000 + round;
                let cb = CountingCallback::new();
                dispatcher_for_thread
                    .register_callback(id, Arc::clone(&cb) as Arc<dyn NotificationCallback>);
                dispatcher_for_thread.unregister_callback(id);
            }
        });

        // Main thread: register one stable callback and fire frames at it.
        let cb = CountingCallback::new();
        dispatcher.register_callback(7, Arc::clone(&cb) as Arc<dyn NotificationCallback>);
        for _ in 0..100 {
            sender
                .send(NotificationFrame {
                    subscription_id: 7,
                    events: NOTIFY_EVENT_IN,
                })
                .unwrap();
        }

        bg.join().unwrap();
        cb.wait_for_count(100, 5000);
        assert_eq!(cb.count.load(Ordering::SeqCst), 100);
    }
}
