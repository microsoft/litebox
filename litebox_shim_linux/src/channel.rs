use core::{
    cell::RefCell,
    sync::atomic::{AtomicBool, Ordering},
};

use alloc::sync::{Arc, Weak};
use litebox::sync::Synchronization;
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;
use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Producer as _, Split as _},
};

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
            if let Some(peer) = self.peer.borrow().upgrade() {
                peer.endpoint.is_shutdown()
            } else {
                true
            }
        }
    };
}

pub(crate) struct Producer<T> {
    endpoint: EndPointer<HeapProd<T>>,
    peer: RefCell<Weak<Consumer<T>>>,
}

impl<T> Producer<T> {
    fn new(rb: HeapProd<T>, platform: &'static Platform) -> Self {
        Self {
            endpoint: EndPointer::new(rb, platform),
            peer: RefCell::new(Weak::new()),
        }
    }

    fn try_write(&self, buf: &[T]) -> Result<usize, Errno>
    where
        T: Copy,
    {
        if self.is_shutdown() || self.is_peer_shutdown() {
            return Err(Errno::EPIPE);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let write_len = self.endpoint.rb.lock().push_slice(buf);
        if write_len > 0 {
            Ok(write_len)
        } else {
            Err(Errno::EAGAIN)
        }
    }

    pub(crate) fn write(&self, buf: &[T], is_nonblocking: bool) -> Result<usize, Errno>
    where
        T: Copy,
    {
        if is_nonblocking {
            self.try_write(buf)
        } else {
            // TODO: use poll rather than busy wait
            loop {
                match self.try_write(buf) {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
            }
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
    endpoint: EndPointer<HeapCons<T>>,
    peer: RefCell<Weak<Producer<T>>>,
}

impl<T> Consumer<T> {
    fn new(rb: HeapCons<T>, platform: &'static Platform) -> Self {
        Self {
            endpoint: EndPointer::new(rb, platform),
            peer: RefCell::new(Weak::new()),
        }
    }

    fn try_read(&self, buf: &mut [T]) -> Result<usize, Errno>
    where
        T: Copy,
    {
        if self.is_shutdown() {
            return Err(Errno::EPIPE);
        }
        if buf.is_empty() {
            return Ok(0);
        }

        let read_len = self.endpoint.rb.lock().pop_slice(buf);

        if self.is_peer_shutdown() {
            return Ok(read_len);
        }

        if read_len > 0 {
            Ok(read_len)
        } else {
            Err(Errno::EAGAIN)
        }
    }

    pub(crate) fn read(&self, buf: &mut [T], is_nonblocking: bool) -> Result<usize, Errno>
    where
        T: Copy,
    {
        if is_nonblocking {
            self.try_read(buf)
        } else {
            // TODO: use poll rather than busy wait
            loop {
                match self.try_read(buf) {
                    Err(Errno::EAGAIN) => {}
                    ret => return ret,
                }
            }
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
    prod: Arc<Producer<T>>,
    cons: Arc<Consumer<T>>,
}

impl<T> Channel<T> {
    pub(crate) fn new(capacity: usize, platform: &'static Platform) -> Self {
        let rb: HeapRb<T> = HeapRb::new(capacity);
        let (rb_prod, rb_cons) = rb.split();

        let producer = Arc::new(Producer::new(rb_prod, platform));
        let consumer = Arc::new(Consumer::new(rb_cons, platform));

        *producer.peer.borrow_mut() = (Arc::downgrade(&consumer));
        *consumer.peer.borrow_mut() = (Arc::downgrade(&producer));

        Self {
            prod: producer,
            cons: consumer,
        }
    }

    /// Turn the channel into a pair of producer and consumer.
    pub(crate) fn split(self) -> (Arc<Producer<T>>, Arc<Consumer<T>>) {
        let Channel { prod, cons } = self;
        (prod, cons)
    }
}
