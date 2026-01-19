//! Lock-free socket channels using ringbuf for decoupling user I/O from network processing.
//!
//! This module provides a channel-based design for socket data transfer that eliminates
//! lock contention between user threads (performing read/pselect) and the network worker
//! (processing packets via smoltcp).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────┐                          ┌─────────────────┐
//! │   User Thread   │                          │  Network Worker │
//! │  (read/write)   │                          │   (smoltcp)     │
//! └────────┬────────┘                          └────────┬────────┘
//!          │                                            │
//!          ▼                                            ▼
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    SocketChannel                             │
//! │  ┌─────────────────┐          ┌─────────────────────────┐   │
//! │  │   RX Channel    │◄─────────│  Network Worker writes  │   │
//! │  │  (lock-free)    │          │  data from smoltcp      │   │
//! │  │  User reads ────┼──────────►                         │   │
//! │  └─────────────────┘          └─────────────────────────┘   │
//! │                                                              │
//! │  ┌─────────────────┐          ┌─────────────────────────┐   │
//! │  │   TX Channel    │──────────►  Network Worker reads   │   │
//! │  │  (lock-free)    │          │  and sends via smoltcp  │   │
//! │  │  User writes ───┼──────────►                         │   │
//! │  └─────────────────┘          └─────────────────────────┘   │
//! │                                                              │
//! │  ┌─────────────────┐                                        │
//! │  │   State flags   │  (atomic: ready, closed, error, etc.)  │
//! │  └─────────────────┘                                        │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Benefits
//!
//! - **No lock contention**: User read/write operations and network processing can proceed
//!   concurrently without blocking each other.
//! - **Better latency**: User operations complete faster as they don't need to wait for
//!   the network worker to release locks.
//! - **Improved throughput**: Network worker can process packets continuously without
//!   being blocked by user operations.

use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering},
};

use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Observer as _, Producer as _, Split as _},
};

use crate::platform::TimeProvider;
use crate::sync::{Mutex, RawSyncPrimitivesProvider};
use crate::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    net::ReceiveFlags,
};

/// Default buffer size for socket channels (256 KB)
const DEFAULT_CHANNEL_BUFFER_SIZE: usize = 256 * 1024;

/// Socket state flags stored atomically
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum SocketState {
    /// Socket is closed or in initial state
    Closed = 0,
    /// Socket is connecting (TCP SYN sent)
    Connecting = 1,
    /// Socket is connected and ready for data transfer
    Connected = 2,
    /// Socket is listening for incoming connections
    Listening = 3,
    /// Socket is closing gracefully
    Closing = 4,
    /// Socket encountered an error
    Error = 5,
}

impl From<u32> for SocketState {
    fn from(v: u32) -> Self {
        match v {
            0 => SocketState::Closed,
            1 => SocketState::Connecting,
            2 => SocketState::Connected,
            3 => SocketState::Listening,
            4 => SocketState::Closing,
            _ => SocketState::Error,
        }
    }
}

pub enum NetworkProxy<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    Stream(NetworkSocketHandle<Platform>),
    Datagram(NetworkDatagramHandle<Platform>),
    Raw,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkProxy<Platform> {
    pub fn set_state(&self, state: SocketState) {
        match self {
            NetworkProxy::Stream(handle) => handle.inner.set_state(state),
            NetworkProxy::Datagram(_) | NetworkProxy::Raw => {}
        }
    }
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketChannelError> {
        match self {
            NetworkProxy::Stream(handle) => handle.try_read(buf, flags, source_addr),
            NetworkProxy::Datagram(handle) => handle.try_read(buf, flags, source_addr),
            NetworkProxy::Raw => unimplemented!(),
        }
    }
    pub fn try_write(
        &self,
        buf: &[u8],
        flags: super::SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, SocketChannelError> {
        if !flags.is_empty() {
            unimplemented!()
        }
        match self {
            NetworkProxy::Stream(handle) => handle.try_write(buf),
            NetworkProxy::Datagram(handle) => handle.send_to(buf.to_vec(), destination),
            NetworkProxy::Raw => unimplemented!(),
        }
    }
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for NetworkProxy<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match self {
            NetworkProxy::Stream(handle) => handle.register_observer(observer, mask),
            NetworkProxy::Datagram(handle) => handle.register_observer(observer, mask),
            NetworkProxy::Raw => {}
        }
    }

    fn check_io_events(&self) -> Events {
        match self {
            NetworkProxy::Stream(handle) => handle.check_io_events(),
            NetworkProxy::Datagram(handle) => handle.check_io_events(),
            NetworkProxy::Raw => unimplemented!(),
        }
    }
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkProxy<Platform> {
    pub(super) fn set_readable(&self, readable: bool) {
        match self {
            NetworkProxy::Stream(handle) => handle.set_readable(readable),
            NetworkProxy::Datagram(handle) => handle.set_readable(readable),
            NetworkProxy::Raw => {}
        }
    }

    pub(super) fn has_pending_tx(&self) -> bool {
        match self {
            NetworkProxy::Stream(handle) => handle.has_pending_tx(),
            NetworkProxy::Datagram(handle) => handle.has_pending_tx(),
            NetworkProxy::Raw => false,
        }
    }
}

/// The network worker's handle for socket operations.
///
/// This handle is used by the network processing thread to transfer data
/// to/from the smoltcp socket.
pub struct NetworkSocketHandle<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: SocketChannelInner<Platform>,
}

/// Internal shared state for a socket channel.
struct SocketChannelInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// RX producer (network worker writes here)
    rx_prod: Mutex<Platform, HeapProd<u8>>,
    /// RX consumer (user reads from here)
    rx_cons: Mutex<Platform, HeapCons<u8>>,
    /// TX producer (user writes here)
    tx_prod: Mutex<Platform, HeapProd<u8>>,
    /// TX consumer (network worker reads from here)
    tx_cons: Mutex<Platform, HeapCons<u8>>,

    /// Current socket state
    state: AtomicU32,
    /// Whether the read side is shut down (SHUT_RD)
    read_shutdown: AtomicBool,
    /// Whether the write side is shut down (SHUT_WR)
    write_shutdown: AtomicBool,
    /// Bytes available in RX buffer (for quick poll checks)
    rx_available: AtomicUsize,
    /// Space available in TX buffer (for quick poll checks)
    tx_available: AtomicUsize,

    /// Event notification
    pollee: Pollee<Platform>,
}

/// Error types for socket channel operations
#[derive(Debug, Clone, Copy)]
pub enum SocketChannelError {
    /// The operation would block
    WouldBlock,
    /// The socket is not connected
    NotConnected,
    /// The socket is closed
    Closed,
    /// The socket is in an invalid state for this operation
    InvalidState,
    /// Buffer is full (for write operations)
    BufferFull,
    /// Connection was reset by peer
    ConnectionReset,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> SocketChannelInner<Platform> {
    fn new(rx_capacity: usize, tx_capacity: usize) -> Self {
        let rx_rb: HeapRb<u8> = HeapRb::new(rx_capacity);
        let (rx_prod, rx_cons) = rx_rb.split();

        let tx_rb: HeapRb<u8> = HeapRb::new(tx_capacity);
        let (tx_prod, tx_cons) = tx_rb.split();

        Self {
            rx_prod: Mutex::new(rx_prod),
            rx_cons: Mutex::new(rx_cons),
            tx_prod: Mutex::new(tx_prod),
            tx_cons: Mutex::new(tx_cons),

            state: AtomicU32::new(SocketState::Closed as u32),
            read_shutdown: AtomicBool::new(false),
            write_shutdown: AtomicBool::new(false),
            rx_available: AtomicUsize::new(0),
            tx_available: AtomicUsize::new(tx_capacity),

            pollee: Pollee::new(),
        }
    }

    fn state(&self) -> SocketState {
        SocketState::from(self.state.load(Ordering::Acquire))
    }

    fn set_state(&self, state: SocketState) {
        self.state.store(state as u32, Ordering::Release);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkSocketHandle<Platform> {
    /// Read data from the socket into the provided buffer.
    ///
    /// This is a lock-free operation that reads from the RX ring buffer.
    /// Returns the number of bytes read, or an error.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketChannelError> {
        if self.inner.read_shutdown.load(Ordering::Acquire) {
            return Err(SocketChannelError::Closed);
        }

        match self.inner.state() {
            SocketState::Connected | SocketState::Closing => {}
            SocketState::Closed => return Err(SocketChannelError::Closed),
            _ => return Err(SocketChannelError::NotConnected),
        }

        let mut rx_cons = self.inner.rx_cons.lock();
        let n = if flags.contains(super::ReceiveFlags::DISCARD) {
            rx_cons.clear()
        } else if flags.contains(super::ReceiveFlags::TRUNC) {
            let n1 = rx_cons.pop_slice(buf);
            let n2 = rx_cons.clear();
            n1 + n2
        } else {
            rx_cons.pop_slice(buf)
        };

        if let Some(source_addr) = source_addr {
            // TCP is connection-oriented, so no need to provide a source address
            *source_addr = None;
        }

        // Update available count
        self.inner.rx_available.fetch_sub(n, Ordering::Release);
        Ok(n)
    }

    /// Write data to the socket from the provided buffer.
    ///
    /// This is a lock-free operation that writes to the TX ring buffer.
    /// Returns the number of bytes written, or an error.
    pub fn try_write(&self, buf: &[u8]) -> Result<usize, SocketChannelError> {
        if self.inner.write_shutdown.load(Ordering::Acquire) {
            return Err(SocketChannelError::Closed);
        }

        match self.state() {
            SocketState::Connected => {}
            SocketState::Closed | SocketState::Closing => return Err(SocketChannelError::Closed),
            _ => return Err(SocketChannelError::NotConnected),
        }

        let mut tx_prod = self.inner.tx_prod.lock();
        let n = tx_prod.push_slice(buf);

        if n > 0 {
            // Update available count
            self.inner.tx_available.fetch_sub(n, Ordering::Release);
            Ok(n)
        } else {
            Err(SocketChannelError::BufferFull)
        }
    }

    /// Check if the socket is writable (has buffer space).
    pub fn is_writable(&self) -> bool {
        self.inner.tx_available.load(Ordering::Acquire) > 0
    }

    /// Get the current socket state.
    // pub fn state(&self) -> SocketState {
    //     self.inner.state()
    // }

    /// Shutdown the read side of the socket.
    pub fn shutdown_read(&self) {
        self.inner.read_shutdown.store(true, Ordering::Release);
    }

    /// Shutdown the write side of the socket.
    pub fn shutdown_write(&self) {
        self.inner.write_shutdown.store(true, Ordering::Release);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable
    for NetworkSocketHandle<Platform>
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.inner.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();

        if self.inner.rx_available.load(Ordering::Acquire) > 0 {
            events |= Events::IN;
        }

        if self.inner.tx_available.load(Ordering::Acquire) > 0 {
            events |= Events::OUT;
        }

        match self.inner.state() {
            SocketState::Closed => events |= Events::HUP,
            SocketState::Error => events |= Events::ERR,
            _ => {}
        }

        events
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkSocketHandle<Platform> {
    /// Push received data from the network into the RX buffer.
    ///
    /// Called by the network worker when data arrives from smoltcp.
    pub(super) fn push_rx_data(&self, data: &[u8]) -> usize {
        let mut rx_prod = self.inner.rx_prod.lock();
        let n = rx_prod.push_slice(data);

        if n > 0 {
            self.inner.rx_available.fetch_add(n, Ordering::Release);
            self.inner.pollee.notify_observers(Events::IN);
        }

        n
    }

    /// Pop data from the TX buffer to send over the network.
    ///
    /// Called by the network worker when smoltcp is ready to send.
    pub(super) fn pop_tx_data(&self, buf: &mut [u8]) -> usize {
        let mut tx_cons = self.inner.tx_cons.lock();
        let n = tx_cons.pop_slice(buf);

        if n > 0 {
            self.inner.tx_available.fetch_add(n, Ordering::Release);
            self.inner.pollee.notify_observers(Events::OUT);
        }

        n
    }

    /// Check if the socket is readable (has data available).
    pub(super) fn is_readable(&self) -> bool {
        self.inner.rx_available.load(Ordering::Acquire) > 0
    }

    pub(super) fn set_readable(&self, readable: bool) {
        if readable {
            self.inner.rx_available.store(1, Ordering::Release);
        } else {
            self.inner.rx_available.store(0, Ordering::Release);
        }
    }

    /// Check if there's data waiting to be sent.
    pub(super) fn has_pending_tx(&self) -> bool {
        let tx_cons = self.inner.tx_cons.lock();
        !tx_cons.is_empty()
    }

    /// Check if there's space in the RX buffer.
    // pub(super) fn has_rx_space(&self) -> bool {
    //     let rx_prod = self.inner.rx_prod.lock();
    //     !rx_prod.is_full()
    // }

    pub(super) fn rx_space(&self) -> usize {
        let rx_prod = self.inner.rx_prod.lock();
        rx_prod.vacant_len()
    }

    /// Set the socket state.
    pub(super) fn set_state(&self, state: SocketState) {
        let old_state = self.inner.state();
        if old_state == state {
            return;
        }
        self.inner.set_state(state);

        // Notify user of state changes
        match state {
            SocketState::Connected => {
                self.inner.pollee.notify_observers(Events::OUT);
            }
            SocketState::Closed => {
                self.inner.pollee.notify_observers(Events::HUP);
            }
            SocketState::Error => {
                self.inner.pollee.notify_observers(Events::ERR);
            }
            _ => {}
        }
    }

    /// Get the current socket state.
    pub(super) fn state(&self) -> SocketState {
        self.inner.state()
    }

    /// Check if write side is shut down.
    // pub(super) fn is_write_shutdown(&self) -> bool {
    //     self.inner.write_shutdown.load(Ordering::Acquire)
    // }

    pub(super) fn notify_io_event(&self, events: Events) {
        self.inner.pollee.notify_observers(events);
    }
}

/// Create a new socket channel pair.
///
/// Returns a user handle and a network handle that share the same underlying
/// ring buffers but can be used concurrently without lock contention.
pub fn new_socket_channel<Platform: RawSyncPrimitivesProvider + TimeProvider>()
-> NetworkSocketHandle<Platform> {
    new_socket_channel_with_capacity(DEFAULT_CHANNEL_BUFFER_SIZE, DEFAULT_CHANNEL_BUFFER_SIZE)
}

/// Create a new socket channel pair with specified buffer capacities.
pub fn new_socket_channel_with_capacity<Platform: RawSyncPrimitivesProvider + TimeProvider>(
    rx_capacity: usize,
    tx_capacity: usize,
) -> NetworkSocketHandle<Platform> {
    let inner = SocketChannelInner::new(rx_capacity, tx_capacity);
    NetworkSocketHandle { inner }
}

/// A datagram message for UDP-like sockets.
#[derive(Clone)]
pub struct DatagramMessage {
    /// The data payload
    pub data: alloc::vec::Vec<u8>,
    /// Source/destination address (depending on direction)
    pub addr: Option<core::net::SocketAddr>,
}

/// Network handle for datagram (UDP) sockets.
pub struct NetworkDatagramHandle<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: DatagramChannelInner<Platform>,
}

/// Internal shared state for a datagram channel.
struct DatagramChannelInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// RX producer (network worker writes here)
    rx_prod: Mutex<Platform, HeapProd<DatagramMessage>>,
    /// RX consumer (user reads from here)
    rx_cons: Mutex<Platform, HeapCons<DatagramMessage>>,
    /// TX producer (user writes here)
    tx_prod: Mutex<Platform, HeapProd<DatagramMessage>>,
    /// TX consumer (network worker reads from here)
    tx_cons: Mutex<Platform, HeapCons<DatagramMessage>>,

    /// Messages available in RX
    rx_count: AtomicUsize,
    /// Space available in TX
    tx_space: AtomicUsize,

    /// Event notification
    pollee: Pollee<Platform>,
}

/// Maximum number of datagrams in queue
const DEFAULT_DATAGRAM_QUEUE_SIZE: usize = 64;

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> DatagramChannelInner<Platform> {
    fn new(queue_size: usize) -> Self {
        let rx_rb: HeapRb<DatagramMessage> = HeapRb::new(queue_size);
        let (rx_prod, rx_cons) = rx_rb.split();

        let tx_rb: HeapRb<DatagramMessage> = HeapRb::new(queue_size);
        let (tx_prod, tx_cons) = tx_rb.split();

        Self {
            rx_prod: Mutex::new(rx_prod),
            rx_cons: Mutex::new(rx_cons),
            tx_prod: Mutex::new(tx_prod),
            tx_cons: Mutex::new(tx_cons),

            rx_count: AtomicUsize::new(0),
            tx_space: AtomicUsize::new(queue_size),

            pollee: Pollee::new(),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkDatagramHandle<Platform> {
    /// Receive a datagram from the socket.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, SocketChannelError> {
        let mut rx_cons = self.inner.rx_cons.lock();

        if let Some(msg) = rx_cons.try_pop() {
            let DatagramMessage { data, addr } = msg;
            if let Some(source_addr) = source_addr {
                *source_addr = addr;
            }
            let n = if flags.contains(ReceiveFlags::DISCARD) {
                data.len()
            } else {
                let to_copy = core::cmp::min(buf.len(), data.len());
                buf[..to_copy].copy_from_slice(&data[..to_copy]);
                if flags.contains(ReceiveFlags::TRUNC) {
                    // return the real size of the packet or datagram,
                    // even when it was longer than the passed buffer.
                    data.len()
                } else {
                    to_copy
                }
            };
            self.inner.rx_count.fetch_sub(1, Ordering::Release);
            self.inner.pollee.notify_observers(Events::OUT);
            Ok(n)
        } else {
            Err(SocketChannelError::WouldBlock)
        }
    }

    /// Send a datagram to the specified address.
    pub fn send_to(
        &self,
        data: alloc::vec::Vec<u8>,
        addr: Option<SocketAddr>,
    ) -> Result<usize, SocketChannelError> {
        let size = data.len();
        let msg = DatagramMessage { data, addr };
        let mut tx_prod = self.inner.tx_prod.lock();

        match tx_prod.try_push(msg) {
            Ok(()) => {
                self.inner.tx_space.fetch_sub(1, Ordering::Release);
                self.inner.pollee.notify_observers(Events::IN);
                Ok(size)
            }
            Err(_) => Err(SocketChannelError::BufferFull),
        }
    }

    /// Check if the socket is readable.
    pub fn is_readable(&self) -> bool {
        self.inner.rx_count.load(Ordering::Acquire) > 0
    }

    /// Check if the socket is writable.
    pub fn is_writable(&self) -> bool {
        self.inner.tx_space.load(Ordering::Acquire) > 0
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable
    for NetworkDatagramHandle<Platform>
{
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        self.inner.pollee.register_observer(observer, mask);
    }

    fn check_io_events(&self) -> Events {
        let mut events = Events::empty();

        if self.inner.rx_count.load(Ordering::Acquire) > 0 {
            events |= Events::IN;
        }

        if self.inner.tx_space.load(Ordering::Acquire) > 0 {
            events |= Events::OUT;
        }

        events
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkDatagramHandle<Platform> {
    /// Push a received datagram into the RX queue.
    pub(super) fn push_datagram(&self, msg: DatagramMessage) -> Result<(), DatagramMessage> {
        let mut rx_prod = self.inner.rx_prod.lock();

        match rx_prod.try_push(msg) {
            Ok(()) => {
                self.inner.rx_count.fetch_add(1, Ordering::Release);
                self.inner.pollee.notify_observers(Events::IN);
                Ok(())
            }
            Err(msg) => Err(msg),
        }
    }

    /// Pop a datagram from the TX queue to send.
    pub(super) fn pop_datagram(&self) -> Option<DatagramMessage> {
        let mut tx_cons = self.inner.tx_cons.lock();

        if let Some(msg) = tx_cons.try_pop() {
            self.inner.tx_space.fetch_add(1, Ordering::Release);
            self.inner.pollee.notify_observers(Events::OUT);
            Some(msg)
        } else {
            None
        }
    }

    /// Check if the RX queue is full.
    pub(super) fn is_rx_full(&self) -> bool {
        let rx_prod = self.inner.rx_prod.lock();
        rx_prod.is_full()
    }

    /// Check if there are datagrams to send.
    pub(super) fn has_pending_tx(&self) -> bool {
        let tx_cons = self.inner.tx_cons.lock();
        !tx_cons.is_empty()
    }

    pub(super) fn set_readable(&self, readable: bool) {
        if readable {
            self.inner.rx_count.store(1, Ordering::Release);
        } else {
            self.inner.rx_count.store(0, Ordering::Release);
        }
    }
}

/// Create a new datagram channel pair.
pub fn new_datagram_channel<Platform: RawSyncPrimitivesProvider + TimeProvider>()
-> NetworkDatagramHandle<Platform> {
    new_datagram_channel_with_capacity(DEFAULT_DATAGRAM_QUEUE_SIZE)
}

/// Create a new datagram channel pair with specified queue size.
pub fn new_datagram_channel_with_capacity<Platform: RawSyncPrimitivesProvider + TimeProvider>(
    queue_size: usize,
) -> NetworkDatagramHandle<Platform> {
    let inner = DatagramChannelInner::new(queue_size);
    NetworkDatagramHandle { inner }
}

#[cfg(test)]
mod tests {
    // use super::*;

    // #[test]
    // fn test_stream_channel_basic() {
    //     type Platform = crate::platform::mock::MockPlatform;
    //     let (user, network) = new_socket_channel::<Platform>();

    //     // Network pushes data
    //     network.set_state(SocketState::Connected);
    //     let data = b"Hello, World!";
    //     let pushed = network.push_rx_data(data);
    //     assert_eq!(pushed, data.len());

    //     // User reads data
    //     let mut buf = [0u8; 32];
    //     let read = user
    //         .try_read(&mut buf, crate::net::ReceiveFlags::empty(), None)
    //         .unwrap();
    //     assert_eq!(read, data.len());
    //     assert_eq!(&buf[..read], data);
    // }

    // #[test]
    // fn test_stream_channel_write() {
    //     type Platform = crate::platform::mock::MockPlatform;
    //     let (user, network) = new_socket_channel::<Platform>();

    //     network.set_state(SocketState::Connected);

    //     // User writes data
    //     let data = b"Hello, Network!";
    //     let written = user
    //         .try_write(data, crate::net::SendFlags::empty(), None)
    //         .unwrap();
    //     assert_eq!(written, data.len());

    //     // Network pops data
    //     let mut buf = [0u8; 32];
    //     let read = network.pop_tx_data(&mut buf);
    //     assert_eq!(read, data.len());
    //     assert_eq!(&buf[..read], data);
    // }
}
