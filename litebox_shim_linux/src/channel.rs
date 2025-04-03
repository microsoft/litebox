use core::sync::atomic::{AtomicBool, Ordering};

use alloc::sync::{Arc, Weak};
use litebox::sync::Synchronization;
use litebox_platform_multiplex::Platform;
use ringbuf::{HeapCons, HeapProd, HeapRb, traits::Split as _};

struct EndPointer<T> {
    rb: litebox::sync::Mutex<'static, Platform, T>,
    is_shutdown: AtomicBool,
}

impl<T> EndPointer<T> {
    pub fn new(rb: T, platform: &'static Platform) -> Self {
        Self {
            rb: Synchronization::new(platform).new_mutex(rb),
            is_shutdown: AtomicBool::new(false),
        }
    }

    fn is_shutdown(&self) -> bool {
        self.is_shutdown.load(Ordering::Acquire)
    }

    fn shutdown(&self) {
        self.is_shutdown.store(true, Ordering::Release);
    }
}

macro_rules! common_functions_for_channel {
    () => {
        pub fn is_shutdown(&self) -> bool {
            self.endpoint.is_shutdown()
        }

        pub fn shutdown(&self) {
            self.endpoint.shutdown();
        }

        pub fn is_peer_shutdown(&self) -> bool {
            if let Some(peer) = self.peer.upgrade() {
                peer.is_shutdown()
            } else {
                true
            }
        }
    };
}

pub(crate) struct Producer<T> {
    endpoint: Arc<EndPointer<HeapProd<T>>>,
    peer: Weak<EndPointer<HeapCons<T>>>,
}

impl<T> Producer<T> {
    fn new(rb: HeapProd<T>, platform: &'static Platform) -> Self {
        Self {
            endpoint: Arc::new(EndPointer::new(rb, platform)),
            peer: Weak::new(),
        }
    }

    common_functions_for_channel!();
}

impl<T> Drop for Producer<T> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) struct Consumer<T> {
    endpoint: Arc<EndPointer<HeapCons<T>>>,
    peer: Weak<EndPointer<HeapProd<T>>>,
}

impl<T> Consumer<T> {
    fn new(rb: HeapCons<T>, platform: &'static Platform) -> Self {
        Self {
            endpoint: Arc::new(EndPointer::new(rb, platform)),
            peer: Weak::new(),
        }
    }

    common_functions_for_channel!();
}

impl<T> Drop for Consumer<T> {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub(crate) struct Channel<T> {
    prod: Producer<T>,
    cons: Consumer<T>,
}

impl<T> Channel<T> {
    pub(crate) fn new(capacity: usize, platform: &'static Platform) -> Self {
        let rb: HeapRb<T> = HeapRb::new(capacity);
        let (rb_prod, rb_cons) = rb.split();

        let mut producer = Producer::new(rb_prod, platform);
        let mut consumer = Consumer::new(rb_cons, platform);

        producer.peer = Arc::downgrade(&consumer.endpoint);
        consumer.peer = Arc::downgrade(&producer.endpoint);

        Self {
            prod: producer,
            cons: consumer,
        }
    }

    /// Turn the channel into a pair of producer and consumer.
    pub(crate) fn split(self) -> (Producer<T>, Consumer<T>) {
        let Channel { prod, cons } = self;
        (prod, cons)
    }
}
