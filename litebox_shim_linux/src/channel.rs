//! This module implements a unidirectional communication channel, intended to implement IPC,
//! e.g., pipe, unix domain sockets, etc.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use alloc::sync::{Arc, Weak};
use litebox::{fs::OFlags, sync::Synchronization};
use litebox_common_linux::errno::Errno;
use litebox_platform_multiplex::Platform;
use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Producer as _, Split as _},
};

struct EndPointer<T> {
    rb: litebox::sync::Mutex<Platform, T>,
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
                peer.endpoint.is_shutdown()
            } else {
                true
            }
        }

        pub(crate) fn get_status(&self) -> OFlags {
            OFlags::from_bits(self.status.load(core::sync::atomic::Ordering::Relaxed)).unwrap()
        }

        pub(crate) fn set_status(&self, flag: OFlags, on: bool) {
            if on {
                self.status
                    .fetch_or(flag.bits(), core::sync::atomic::Ordering::Relaxed);
            } else {
                self.status.fetch_and(
                    flag.complement().bits(),
                    core::sync::atomic::Ordering::Relaxed,
                );
            }
        }
    };
}

pub(crate) struct Producer<T> {
    endpoint: EndPointer<HeapProd<T>>,
    peer: Weak<Consumer<T>>,
    /// File status flags (see [`OFlags::STATUS_FLAGS_MASK`])
    status: AtomicU32,
}

impl<T> Producer<T> {
    fn new(rb: HeapProd<T>, flags: OFlags, platform: &'static Platform) -> Self {
        Self {
            endpoint: EndPointer::new(rb, platform),
            peer: Weak::new(),
            status: AtomicU32::new((flags & OFlags::STATUS_FLAGS_MASK).bits()),
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
                core::hint::spin_loop();
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
    peer: Weak<Producer<T>>,
    status: AtomicU32,
}

impl<T> Consumer<T> {
    fn new(rb: HeapCons<T>, flags: OFlags, platform: &'static Platform) -> Self {
        Self {
            endpoint: EndPointer::new(rb, platform),
            peer: Weak::new(),
            status: AtomicU32::new((flags & OFlags::STATUS_FLAGS_MASK).bits()),
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
        if read_len > 0 {
            Ok(read_len)
        } else {
            if self.is_peer_shutdown() {
                // Note: we need to read again to ensure no data sent between `pop_slice`
                // and `is_peer_shutdown` are lost.
                return Ok(self.endpoint.rb.lock().pop_slice(buf));
            }
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
                core::hint::spin_loop();
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

/// A unidirectional communication channel, intended to implement IPC, e.g., pipe,
/// unix domain sockets, etc.
pub(crate) struct Channel<T> {
    prod: Arc<Producer<T>>,
    cons: Arc<Consumer<T>>,
}

impl<T> Channel<T> {
    /// Creates a new channel with the given capacity and flags.
    pub(crate) fn new(capacity: usize, flags: OFlags, platform: &'static Platform) -> Self {
        let rb: HeapRb<T> = HeapRb::new(capacity);
        let (rb_prod, rb_cons) = rb.split();

        // Create the producer and consumer, and set up cyclic references.
        let mut producer = Arc::new(Producer::new(rb_prod, flags, platform));
        let consumer = Arc::new_cyclic(|weak_self| {
            // Producer has no other references as it is just created.
            // So we can safely get a mutable reference to it.
            Arc::get_mut(&mut producer).unwrap().peer = weak_self.clone();
            let mut consumer = Consumer::new(rb_cons, flags, platform);
            consumer.peer = Arc::downgrade(&producer);
            consumer
        });

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

#[cfg(test)]
mod tests {
    use litebox::platform::trivial_providers::ImpossiblePunchthroughProvider;
    use litebox_common_linux::errno::Errno;
    use litebox_platform_multiplex::{Platform, set_platform};

    extern crate std;

    fn init_platform() {
        let platform = alloc::boxed::Box::leak(alloc::boxed::Box::new(Platform::new(
            None,
            ImpossiblePunchthroughProvider {},
        )));
        set_platform(&*platform);
    }

    #[test]
    fn test_blocking_channel() {
        init_platform();

        let (prod, cons) = super::Channel::<u8>::new(
            2,
            litebox::fs::OFlags::empty(),
            litebox_platform_multiplex::platform(),
        )
        .split();
        std::thread::spawn(move || {
            let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut i = 0;
            while i < data.len() {
                let ret = prod.write(&data[i..], false).unwrap();
                i += ret;
            }
            prod.shutdown();
            assert_eq!(i, data.len());
        });

        let mut buf = [0; 10];
        let mut i = 0;
        loop {
            let ret = cons.read(&mut buf[i..], false).unwrap();
            if ret == 0 {
                cons.shutdown();
                break;
            }
            i += ret;
        }
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }

    #[test]
    fn test_nonblocking_channel() {
        init_platform();

        let (prod, cons) = super::Channel::<u8>::new(
            2,
            litebox::fs::OFlags::empty(),
            litebox_platform_multiplex::platform(),
        )
        .split();
        std::thread::spawn(move || {
            let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];
            let mut i = 0;
            while i < data.len() {
                match prod.write(&data[i..], true) {
                    Ok(n) => {
                        i += n;
                    }
                    Err(Errno::EAGAIN) => {
                        // busy wait
                        // TODO: use poll rather than busy wait
                    }
                    Err(e) => {
                        panic!("Error writing to channel: {:?}", e);
                    }
                }
            }
            prod.shutdown();
            assert_eq!(i, data.len());
        });

        let mut buf = [0; 10];
        let mut i = 0;
        loop {
            match cons.read(&mut buf[i..], true) {
                Ok(n) => {
                    if n == 0 {
                        break;
                    }
                    i += n;
                }
                Err(Errno::EAGAIN) => {
                    // busy wait
                    // TODO: use poll rather than busy wait
                }
                Err(e) => {
                    panic!("Error reading from channel: {:?}", e);
                }
            }
        }
        assert_eq!(buf, [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
}
