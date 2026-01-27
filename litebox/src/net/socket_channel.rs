// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

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
//! │                    SocketChannel                            │
//! │  ┌─────────────────┐          ┌─────────────────────────┐   │
//! │  │   RX Channel    │◄─────────│  Network Worker writes  │   │
//! │  │  (lock-free)    │          │  data from smoltcp      │   │
//! │  │  User reads ────┼──────────►                         │   │
//! │  └─────────────────┘          └─────────────────────────┘   │
//! │                                                             │
//! │  ┌─────────────────┐          ┌─────────────────────────┐   │
//! │  │   TX Channel    │──────────►  Network Worker reads   │   │
//! │  │  (lock-free)    │          │  and sends via smoltcp  │   │
//! │  │  User writes ───┼──────────►                         │   │
//! │  └─────────────────┘          └─────────────────────────┘   │
//! │                                                             │
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

use alloc::boxed::Box;
use core::{
    net::SocketAddr,
    sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicUsize, Ordering},
};

use ringbuf::{
    HeapCons, HeapProd, HeapRb,
    traits::{Consumer as _, Observer as _, Producer as _, Split as _},
};

use crate::sync::{Mutex, RawSyncPrimitivesProvider};
use crate::{
    event::{Events, IOPollable, observer::Observer, polling::Pollee},
    net::ReceiveFlags,
};
use crate::{
    net::errors::{ReceiveError, SendError},
    platform::TimeProvider,
};

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
    /// Socket encountered an error
    Error = 4,
}

impl From<u32> for SocketState {
    fn from(v: u32) -> Self {
        match v {
            0 => SocketState::Closed,
            1 => SocketState::Connecting,
            2 => SocketState::Connected,
            3 => SocketState::Listening,
            _ => SocketState::Error,
        }
    }
}

/// A proxy for network socket operations that decouples user I/O from network processing.
///
/// This enum wraps different socket handle types (stream, datagram, raw) and provides
/// a unified interface for the network layer to interact with sockets.
/// The proxy enables lock-free communication between user threads and the network worker.
pub enum NetworkProxy<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    /// Stream (TCP) socket proxy
    Stream(StreamSocketChannel<Platform>),
    /// Datagram (UDP) socket proxy
    Datagram(DatagramSocketChannel<Platform>),
    /// Raw socket proxy (not yet implemented)
    Raw,
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkProxy<Platform> {
    /// Set the socket state (only applicable to stream sockets).
    pub fn set_state(&self, state: SocketState) {
        match self {
            NetworkProxy::Stream(channel) => channel.set_state(state),
            NetworkProxy::Datagram(_) | NetworkProxy::Raw => {}
        }
    }

    /// Attempt to read data from the socket into the provided buffer.
    ///
    /// Returns the number of bytes read, or an error if the operation would block
    /// or the socket is in an invalid state.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ReceiveError> {
        match self {
            NetworkProxy::Stream(channel) => channel.try_read(buf, flags, source_addr),
            NetworkProxy::Datagram(channel) => channel.try_read(buf, flags, source_addr),
            NetworkProxy::Raw => unimplemented!(),
        }
    }

    /// Attempt to write data to the socket from the provided buffer.
    ///
    /// Returns the number of bytes written, or an error if the buffer is full
    /// or the socket is in an invalid state.
    pub fn try_write(
        &self,
        buf: &[u8],
        flags: super::SendFlags,
        destination: Option<SocketAddr>,
    ) -> Result<usize, SendError> {
        if !flags.is_empty() {
            unimplemented!()
        }
        match self {
            NetworkProxy::Stream(channel) => channel.try_write(buf),
            NetworkProxy::Datagram(channel) => channel.send_to(buf, destination),
            NetworkProxy::Raw => unimplemented!(),
        }
    }
}
impl<Platform: RawSyncPrimitivesProvider + TimeProvider> IOPollable for NetworkProxy<Platform> {
    fn register_observer(&self, observer: alloc::sync::Weak<dyn Observer<Events>>, mask: Events) {
        match self {
            NetworkProxy::Stream(channel) => channel.register_observer(observer, mask),
            NetworkProxy::Datagram(channel) => channel.register_observer(observer, mask),
            NetworkProxy::Raw => {}
        }
    }

    fn check_io_events(&self) -> Events {
        match self {
            NetworkProxy::Stream(channel) => channel.check_io_events(),
            NetworkProxy::Datagram(channel) => channel.check_io_events(),
            NetworkProxy::Raw => unimplemented!(),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> NetworkProxy<Platform> {
    /// Manually set the readable state.
    ///
    /// This is used for server sockets to indicate that a connection is ready to accept.
    pub(super) fn set_readable(&self, readable: bool) {
        match self {
            NetworkProxy::Stream(channel) => channel.set_readable(readable),
            NetworkProxy::Datagram(channel) => channel.set_readable(readable),
            NetworkProxy::Raw => {}
        }
    }

    /// Check if there is data pending in the TX buffer to be sent.
    pub(super) fn has_pending_tx(&self) -> bool {
        match self {
            NetworkProxy::Stream(channel) => channel.has_pending_tx(),
            NetworkProxy::Datagram(channel) => channel.has_pending_tx(),
            NetworkProxy::Raw => false,
        }
    }

    /// Get the local port for datagram sockets (lock-free).
    ///
    /// Returns `Some(port)` for datagram sockets (0 if unbound), `None` for other socket types.
    pub fn datagram_local_port(&self) -> Option<u16> {
        match self {
            NetworkProxy::Datagram(channel) => Some(channel.local_port()),
            _ => None,
        }
    }

    /// Set the local port for datagram sockets (lock-free, one-time operation).
    ///
    /// Uses compare-and-swap to ensure only one thread sets the port.
    /// Returns `Ok(())` if set successfully, `Err(current_port)` if already set.
    /// Returns `Ok(())` for non-datagram sockets (no-op).
    pub fn set_datagram_local_port(&self, port: u16) -> Result<(), u16> {
        match self {
            NetworkProxy::Datagram(channel) => channel.set_local_port(port),
            _ => Ok(()),
        }
    }
}

/// A channel for stream (TCP) socket communication.
///
/// This channel provides lock-free data transfer between user threads and the network
/// worker. User threads write to the TX buffer and read from the RX buffer, while
/// the network worker drains TX to smoltcp and fills RX from smoltcp.
///
/// # Thread Safety
///
/// The channel uses lock-free ring buffers for data transfer, with atomic counters
/// for tracking buffer availability. This allows concurrent access without blocking.
pub struct StreamSocketChannel<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: StreamChannelInner<Platform>,
}

/// Internal state for a stream socket channel.
struct StreamChannelInner<Platform: RawSyncPrimitivesProvider + TimeProvider> {
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> StreamChannelInner<Platform> {
    /// Create a new stream channel with the specified RX and TX buffer capacities.
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

    /// Get the current socket state.
    fn state(&self) -> SocketState {
        SocketState::from(self.state.load(Ordering::Acquire))
    }

    /// Set the socket state.
    fn set_state(&self, state: SocketState) {
        self.state.store(state as u32, Ordering::Release);
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> StreamSocketChannel<Platform> {
    /// Read data from the socket into the provided buffer.
    ///
    /// This reads from the RX ring buffer without blocking.
    /// Returns the number of bytes read, or an error if the socket is closed
    /// or not connected.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ReceiveError> {
        if self.inner.read_shutdown.load(Ordering::Acquire) {
            return Err(ReceiveError::SocketInInvalidState);
        }

        match self.inner.state() {
            SocketState::Connected => {}
            _ => return Err(ReceiveError::SocketInInvalidState),
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
    /// This writes to the TX ring buffer without blocking. The data will be
    /// drained by the network worker and sent via smoltcp.
    ///
    /// Returns the number of bytes written, or an error if the socket is closed,
    /// not connected, or the buffer is full.
    pub fn try_write(&self, buf: &[u8]) -> Result<usize, SendError> {
        if self.inner.write_shutdown.load(Ordering::Acquire) {
            return Err(SendError::SocketInInvalidState);
        }

        match self.state() {
            SocketState::Connected => {}
            _ => return Err(SendError::SocketInInvalidState),
        }

        let mut tx_prod = self.inner.tx_prod.lock();
        let n = tx_prod.push_slice(buf);

        if n > 0 {
            // Update available count
            self.inner.tx_available.fetch_sub(n, Ordering::Release);
            Ok(n)
        } else {
            Err(SendError::BufferFull)
        }
    }

    /// Check if the socket is writable (has buffer space).
    pub fn is_writable(&self) -> bool {
        self.inner.tx_available.load(Ordering::Acquire) > 0
    }

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
    for StreamSocketChannel<Platform>
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> StreamSocketChannel<Platform> {
    /// Push received data from the network into the RX buffer using zero-copy access.
    ///
    /// The closure receives mutable slices directly into the ring buffer.
    /// Returns the total number of bytes written.
    ///
    /// The closure should return how many bytes it wrote to each slice.
    pub(super) fn push_rx_data_with<F>(&self, mut f: F) -> usize
    where
        F: FnMut(&mut [u8]) -> usize,
    {
        let mut rx_prod = self.inner.rx_prod.lock();
        let (first, second) = (*rx_prod).vacant_slices_mut();

        // SAFETY: We're treating maybe_uninit<u8> slices as &mut [u8].
        // This is safe because:
        // 1. u8 has no drop implementation or invalid bit patterns
        // 2. The closure will write to these bytes before we advance the write index
        // 3. We only advance by the number of bytes actually written
        let first: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(first.as_mut_ptr().cast::<u8>(), first.len())
        };
        let second: &mut [u8] = unsafe {
            core::slice::from_raw_parts_mut(second.as_mut_ptr().cast::<u8>(), second.len())
        };

        let mut total = 0;

        // Fill first slice
        if !first.is_empty() {
            let written = f(first);
            total += written;
        }

        // Fill second slice if we have filled all of the first
        if total == first.len() && !second.is_empty() {
            let written = f(second);
            total += written;
        }

        if total > 0 {
            unsafe { (*rx_prod).advance_write_index(total) };
            self.inner.rx_available.fetch_add(total, Ordering::Release);
            self.inner.pollee.notify_observers(Events::IN);
        }

        total
    }

    /// Pop data from the TX buffer to send over the network.
    ///
    /// Called by the network worker when smoltcp is ready to send.
    /// Returns the number of bytes popped into `buf`.
    #[cfg(test)]
    pub(super) fn pop_tx_data(&self, buf: &mut [u8]) -> usize {
        let mut tx_cons = self.inner.tx_cons.lock();
        let n = tx_cons.pop_slice(buf);

        if n > 0 {
            self.inner.tx_available.fetch_add(n, Ordering::Release);
            self.inner.pollee.notify_observers(Events::OUT);
        }

        n
    }

    /// Pop data from the TX buffer using zero-copy access.
    ///
    /// The closure receives slices of data directly from the ring buffer.
    /// Returns the total number of bytes consumed.
    ///
    /// The closure should return how many bytes it consumed from each slice.
    /// This allows partial consumption (e.g., if smoltcp's send buffer is full).
    pub(super) fn pop_tx_data_with<F>(&self, mut f: F) -> usize
    where
        F: FnMut(&[u8]) -> usize,
    {
        let tx_cons = self.inner.tx_cons.lock();
        let (first, second) = tx_cons.as_slices();

        let mut total = 0;

        // Process first slice
        if !first.is_empty() {
            let consumed = f(first);
            total += consumed;
        }

        // Process second slice if we have consumed all of the first
        if total == first.len() && !second.is_empty() {
            let consumed = f(second);
            total += consumed;
        }

        if total > 0 {
            unsafe { tx_cons.advance_read_index(total) };
            self.inner.tx_available.fetch_add(total, Ordering::Release);
            self.inner.pollee.notify_observers(Events::OUT);
        }

        total
    }

    /// Check if the socket has data available for reading.
    pub(super) fn is_readable(&self) -> bool {
        self.inner.rx_available.load(Ordering::Acquire) > 0
    }

    /// Manually set the readable state.
    ///
    /// This is used for server sockets to indicate that a connection is ready to accept.
    pub(super) fn set_readable(&self, readable: bool) {
        if readable {
            self.inner.rx_available.store(1, Ordering::Release);
        } else {
            self.inner.rx_available.store(0, Ordering::Release);
        }
    }

    /// Check if there is data in the TX buffer waiting to be sent.
    pub(super) fn has_pending_tx(&self) -> bool {
        let tx_cons = self.inner.tx_cons.lock();
        !tx_cons.is_empty()
    }

    /// Get the available space in the RX buffer.
    ///
    /// This indicates how many bytes can be pushed before the buffer is full.
    #[cfg(test)]
    pub(super) fn rx_space(&self) -> usize {
        let rx_prod = self.inner.rx_prod.lock();
        rx_prod.vacant_len()
    }

    /// Set the socket state and notify observers of state changes.
    ///
    /// State transitions trigger appropriate event notifications:
    /// - `Connected` -> `Events::OUT` (socket is now writable)
    /// - `Closed` -> `Events::HUP` (hang up)
    /// - `Error` -> `Events::ERR` (error condition)
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

    /// Notify observers of an I/O event.
    pub(super) fn notify_io_event(&self, events: Events) {
        self.inner.pollee.notify_observers(events);
    }
}

/// Create a new stream socket channel with default buffer sizes.
///
/// The channel is created with default buffer sizes [`super::SOCKET_BUFFER_SIZE`] for both
/// RX and TX buffers.
pub fn new_stream_channel<Platform: RawSyncPrimitivesProvider + TimeProvider>()
-> StreamSocketChannel<Platform> {
    new_stream_channel_with_capacity(super::SOCKET_BUFFER_SIZE, super::SOCKET_BUFFER_SIZE)
}

/// Create a new stream socket channel with specified buffer capacities.
///
/// # Arguments
///
/// * `rx_capacity` - Size of the receive buffer in bytes
/// * `tx_capacity` - Size of the transmit buffer in bytes
pub fn new_stream_channel_with_capacity<Platform: RawSyncPrimitivesProvider + TimeProvider>(
    rx_capacity: usize,
    tx_capacity: usize,
) -> StreamSocketChannel<Platform> {
    let inner = StreamChannelInner::new(rx_capacity, tx_capacity);
    StreamSocketChannel { inner }
}

/// A datagram message for UDP-like sockets.
///
/// Each datagram carries its payload and an optional address:
/// - For received datagrams: the source address
/// - For sent datagrams: the destination address (or `None` if using a connected socket)
#[derive(Clone, Debug)]
pub struct DatagramMessage {
    /// The data payload
    pub data: Box<[u8]>,
    /// Source address (for RX) or destination address (for TX)
    pub addr: Option<core::net::SocketAddr>,
}

/// A channel for datagram (UDP) socket communication.
///
/// Unlike [`StreamSocketChannel`], this channel operates on discrete messages
/// rather than a byte stream. Each datagram is queued independently and includes
/// its associated address.
///
/// # Capacity
///
/// The channel has a fixed queue size for datagrams.
pub struct DatagramSocketChannel<Platform: RawSyncPrimitivesProvider + TimeProvider> {
    inner: DatagramChannelInner<Platform>,
}

/// Internal state for a datagram socket channel.
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

    /// Local port the socket is bound to (0 if unbound).
    /// This is set atomically when auto-binding during sendto.
    local_port: AtomicU16,

    /// Event notification
    pollee: Pollee<Platform>,
}

/// Maximum number of datagrams in queue
const DEFAULT_DATAGRAM_QUEUE_SIZE: usize = 64;

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> DatagramChannelInner<Platform> {
    /// Create a new datagram channel with the specified queue size.
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

            local_port: AtomicU16::new(0),

            pollee: Pollee::new(),
        }
    }
}

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> DatagramSocketChannel<Platform> {
    /// Receive a datagram from the socket.
    ///
    /// Copies the datagram payload into `buf` and optionally returns the source address.
    /// If the datagram is larger than `buf`, behavior depends on `flags`.
    pub fn try_read(
        &self,
        buf: &mut [u8],
        flags: super::ReceiveFlags,
        source_addr: Option<&mut Option<SocketAddr>>,
    ) -> Result<usize, ReceiveError> {
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
            Ok(0)
        }
    }

    /// Send a datagram to the specified address.
    ///
    /// The datagram is queued for transmission by the network worker.
    /// Returns the number of bytes queued (always `data.len()` on success).
    pub fn send_to(&self, data: &[u8], addr: Option<SocketAddr>) -> Result<usize, SendError> {
        if let Some(addr) = addr {
            if addr.port() == 0 {
                return Err(SendError::Unaddressable);
            }
            if addr.ip().is_unspecified() {
                return Err(SendError::Unaddressable);
            }
        }

        let size = data.len();
        let msg = DatagramMessage {
            data: data.into(),
            addr,
        };
        let mut tx_prod = self.inner.tx_prod.lock();

        match tx_prod.try_push(msg) {
            Ok(()) => {
                self.inner.tx_space.fetch_sub(1, Ordering::Release);
                self.inner.pollee.notify_observers(Events::IN);
                Ok(size)
            }
            Err(_) => Err(SendError::BufferFull),
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
    for DatagramSocketChannel<Platform>
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

impl<Platform: RawSyncPrimitivesProvider + TimeProvider> DatagramSocketChannel<Platform> {
    /// Try to receive a datagram using a closure that provides the data.
    ///
    /// The closure should return `Some((data, source_addr))` if a datagram was received,
    /// or `None` if no datagram is available. The datagram is pushed to the RX queue
    /// only if the queue has space.
    ///
    /// Returns:
    /// - `Some(len)` if a datagram was received and pushed (len is data length)
    /// - `None` if the closure returned `None` or the queue is full
    pub(super) fn try_recv_datagram_with<F>(&self, f: F) -> Option<usize>
    where
        F: FnOnce() -> Option<(Box<[u8]>, SocketAddr)>,
    {
        let mut rx_prod = self.inner.rx_prod.lock();

        if rx_prod.is_full() {
            return None;
        }

        let (data, source_addr) = f()?;
        let len = data.len();

        let msg = DatagramMessage {
            data,
            addr: Some(source_addr),
        };

        match rx_prod.try_push(msg) {
            Ok(()) => {
                self.inner.rx_count.fetch_add(1, Ordering::Release);
                self.inner.pollee.notify_observers(Events::IN);
                Some(len)
            }
            Err(_) => None,
        }
    }

    /// Try to send the next datagram using a closure, consuming it only on success.
    ///
    /// The closure receives the data slice and optional destination address, and should
    /// return `true` if the send succeeded (datagram will be consumed) or `false` if
    /// the send failed (datagram remains in queue for retry).
    ///
    /// Returns:
    /// - `Some(true)` if a datagram was sent and consumed
    /// - `Some(false)` if a datagram was peeked but send failed (still in queue)
    /// - `None` if the queue is empty
    pub(super) fn try_send_datagram_with<F>(&self, f: F) -> Option<bool>
    where
        F: FnOnce(&[u8], Option<SocketAddr>) -> bool,
    {
        let mut tx_cons = self.inner.tx_cons.lock();

        let msg = tx_cons.iter().next()?;
        let success = f(&msg.data, msg.addr);

        if success {
            // Send succeeded, consume the datagram
            let consumed = tx_cons.try_pop();
            assert!(consumed.is_some());
            self.inner.tx_space.fetch_add(1, Ordering::Release);
            self.inner.pollee.notify_observers(Events::OUT);
        }

        Some(success)
    }

    /// Check if the RX queue is full (cannot accept more datagrams).
    #[cfg(test)]
    pub(super) fn is_rx_full(&self) -> bool {
        let rx_prod = self.inner.rx_prod.lock();
        rx_prod.is_full()
    }

    /// Check if there are datagrams waiting to be sent.
    pub(super) fn has_pending_tx(&self) -> bool {
        let tx_cons = self.inner.tx_cons.lock();
        !tx_cons.is_empty()
    }

    /// Manually set the readable state.
    pub(super) fn set_readable(&self, readable: bool) {
        if readable {
            self.inner.rx_count.store(1, Ordering::Release);
        } else {
            self.inner.rx_count.store(0, Ordering::Release);
        }
    }

    /// Get the local port the socket is bound to.
    ///
    /// Returns 0 if the socket is not yet bound.
    /// This is a lock-free operation.
    pub fn local_port(&self) -> u16 {
        self.inner.local_port.load(Ordering::Acquire)
    }

    /// Set the local port the socket is bound to.
    ///
    /// This should be called when the socket is bound (either explicitly or via auto-binding).
    /// Uses compare-and-swap to ensure only one thread can set the port.
    ///
    /// Returns `Ok(())` if the port was set successfully, or `Err(current_port)` if
    /// a port was already set.
    pub fn set_local_port(&self, port: u16) -> Result<(), u16> {
        match self
            .inner
            .local_port
            .compare_exchange(0, port, Ordering::AcqRel, Ordering::Acquire)
        {
            Ok(_) => Ok(()),
            Err(current) => Err(current),
        }
    }
}

/// Create a new datagram socket channel with default queue size.
///
/// The channel is created with default queue size (64 messages).
pub fn new_datagram_channel<Platform: RawSyncPrimitivesProvider + TimeProvider>()
-> DatagramSocketChannel<Platform> {
    new_datagram_channel_with_capacity(DEFAULT_DATAGRAM_QUEUE_SIZE)
}

/// Create a new datagram socket channel with specified queue size.
///
/// # Arguments
///
/// * `queue_size` - Maximum number of datagrams that can be queued
pub fn new_datagram_channel_with_capacity<Platform: RawSyncPrimitivesProvider + TimeProvider>(
    queue_size: usize,
) -> DatagramSocketChannel<Platform> {
    let inner = DatagramChannelInner::new(queue_size);
    DatagramSocketChannel { inner }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::mock::MockPlatform;

    type TestPlatform = MockPlatform;

    // ==================== StreamSocketChannel Tests ====================

    #[test]
    fn stream_channel_initial_state() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();

        // Initial state should be Closed
        assert_eq!(channel.state(), SocketState::Closed);

        // Should not be readable initially
        assert!(!channel.is_readable());

        // Should be writable (buffer is empty)
        assert!(channel.is_writable());

        // No pending TX data
        assert!(!channel.has_pending_tx());
    }

    #[test]
    fn stream_channel_push_rx_and_read() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();
        channel.set_state(SocketState::Connected);

        // Push data from "network" side
        let data = b"Hello, World!";
        let pushed = channel.push_rx_data_with(|buf| {
            let to_copy = core::cmp::min(buf.len(), data.len());
            buf[..to_copy].copy_from_slice(&data[..to_copy]);
            to_copy
        });
        assert_eq!(pushed, data.len());

        // Should now be readable
        assert!(channel.is_readable());

        // Read from "user" side
        let mut buf = [0u8; 32];
        let read = channel
            .try_read(&mut buf, super::super::ReceiveFlags::empty(), None)
            .unwrap();
        assert_eq!(read, data.len());
        assert_eq!(&buf[..read], data);

        // Should no longer be readable
        assert!(!channel.is_readable());
    }

    #[test]
    fn stream_channel_write_and_pop_tx() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();
        channel.set_state(SocketState::Connected);

        // Write from "user" side
        let data = b"Hello, Network!";
        let written = channel.try_write(data).unwrap();
        assert_eq!(written, data.len());

        // Should have pending TX
        assert!(channel.has_pending_tx());

        // Pop from "network" side
        let mut buf = [0u8; 32];
        let popped = channel.pop_tx_data(&mut buf);
        assert_eq!(popped, data.len());
        assert_eq!(&buf[..popped], data);

        // No more pending TX
        assert!(!channel.has_pending_tx());
    }

    #[test]
    fn stream_channel_not_connected() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();

        // Try to read while not connected
        let mut buf = [0u8; 32];
        let result = channel.try_read(&mut buf, super::super::ReceiveFlags::empty(), None);
        assert!(matches!(result, Err(ReceiveError::SocketInInvalidState)));

        // Try to write while not connected
        let data = b"test";
        let result = channel.try_write(data);
        assert!(matches!(result, Err(SendError::SocketInInvalidState)));
    }

    #[test]
    fn stream_channel_shutdown_read() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();
        channel.set_state(SocketState::Connected);

        // Push some data
        let data = b"data";
        channel.push_rx_data_with(|buf| {
            let to_copy = core::cmp::min(buf.len(), data.len());
            buf[..to_copy].copy_from_slice(&data[..to_copy]);
            to_copy
        });

        // Shutdown read side
        channel.shutdown_read();

        // Should fail to read
        let mut buf = [0u8; 32];
        let result = channel.try_read(&mut buf, super::super::ReceiveFlags::empty(), None);
        assert!(matches!(result, Err(ReceiveError::SocketInInvalidState)));
    }

    #[test]
    fn stream_channel_shutdown_write() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();
        channel.set_state(SocketState::Connected);

        // Shutdown write side
        channel.shutdown_write();

        // Should fail to write
        let result = channel.try_write(b"data");
        assert!(matches!(result, Err(SendError::SocketInInvalidState)));
    }

    #[test]
    fn stream_channel_rx_space() {
        let capacity = 1024;
        let channel: StreamSocketChannel<TestPlatform> =
            new_stream_channel_with_capacity(capacity, capacity);
        channel.set_state(SocketState::Connected);

        // Initially all space is available
        assert_eq!(channel.rx_space(), capacity);

        // Push some data
        let pushed = channel.push_rx_data_with(|buf| {
            let to_write = core::cmp::min(buf.len(), 100);
            buf[..to_write].fill(0);
            to_write
        });
        assert_eq!(pushed, 100);

        // Space should decrease
        assert_eq!(channel.rx_space(), capacity - 100);
    }

    #[test]
    fn stream_channel_partial_read() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();
        channel.set_state(SocketState::Connected);

        // Push 100 bytes
        let pushed = channel.push_rx_data_with(|buf| {
            let to_write = core::cmp::min(buf.len(), 100);
            buf[..to_write].fill(42);
            to_write
        });
        assert_eq!(pushed, 100);

        // Read only 50 bytes
        let mut buf = [0u8; 50];
        let read = channel
            .try_read(&mut buf, super::super::ReceiveFlags::empty(), None)
            .unwrap();
        assert_eq!(read, 50);
        assert!(buf.iter().all(|&b| b == 42));

        // Should still be readable (50 bytes remaining)
        assert!(channel.is_readable());

        // Read remaining
        let read = channel
            .try_read(&mut buf, super::super::ReceiveFlags::empty(), None)
            .unwrap();
        assert_eq!(read, 50);
    }

    #[test]
    fn stream_channel_io_events() {
        let channel: StreamSocketChannel<TestPlatform> = new_stream_channel();

        // Closed state should have HUP
        let events = channel.check_io_events();
        assert!(events.contains(Events::HUP));

        // Connected with empty RX and available TX
        channel.set_state(SocketState::Connected);
        let events = channel.check_io_events();
        assert!(!events.contains(Events::IN)); // No data to read
        assert!(events.contains(Events::OUT)); // Can write

        // Push data to RX
        let data = b"data";
        channel.push_rx_data_with(|buf| {
            let to_copy = core::cmp::min(buf.len(), data.len());
            buf[..to_copy].copy_from_slice(&data[..to_copy]);
            to_copy
        });
        let events = channel.check_io_events();
        assert!(events.contains(Events::IN)); // Data available
        assert!(events.contains(Events::OUT)); // Can still write
    }

    // ==================== DatagramSocketChannel Tests ======================================

    #[test]
    fn datagram_channel_initial_state() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        // Should not be readable initially
        assert!(!channel.is_readable());

        // Should be writable (queue is empty)
        assert!(channel.is_writable());

        // No pending TX
        assert!(!channel.has_pending_tx());

        // RX not full
        assert!(!channel.is_rx_full());
    }

    #[test]
    fn datagram_channel_send_and_receive() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        // Send a datagram (user side)
        let addr = Some(core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            8080,
        )));
        let result = channel.send_to(b"Hello, UDP!", addr);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 11);

        // Should have pending TX
        assert!(channel.has_pending_tx());

        // Pop from network side using try_send_datagram_with
        let mut received_data = None;
        let mut received_addr = None;
        let result = channel.try_send_datagram_with(|data, dest| {
            received_data = Some(data.to_vec());
            received_addr = Some(dest);
            true // consume the datagram
        });
        assert_eq!(result, Some(true));
        assert_eq!(received_data.unwrap(), b"Hello, UDP!");
        assert_eq!(received_addr.unwrap(), addr);

        // No more pending TX
        assert!(!channel.has_pending_tx());
    }

    #[test]
    fn datagram_channel_push_and_read() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        // Push a datagram (network side) using try_recv_datagram_with
        let addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(192, 168, 1, 1),
            1234,
        ));
        let result =
            channel.try_recv_datagram_with(|| Some((Box::from(*b"Incoming packet"), addr)));
        assert_eq!(result, Some(15));

        // Should be readable
        assert!(channel.is_readable());

        // Read from user side
        let mut buf = [0u8; 64];
        let mut source = None;
        let read = channel
            .try_read(
                &mut buf,
                super::super::ReceiveFlags::empty(),
                Some(&mut source),
            )
            .unwrap();
        assert_eq!(read, 15);
        assert_eq!(&buf[..read], b"Incoming packet");
        assert_eq!(source, Some(addr));
    }

    #[test]
    fn datagram_channel_read_empty() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        // Try to read when empty
        let mut buf = [0u8; 64];
        let result = channel.try_read(&mut buf, super::super::ReceiveFlags::empty(), None);
        assert!(matches!(result, Ok(0)));
    }

    #[test]
    fn datagram_channel_queue_full() {
        let queue_size = 4;
        let channel: DatagramSocketChannel<TestPlatform> =
            new_datagram_channel_with_capacity(queue_size);

        // Fill the TX queue
        for i in 0..queue_size {
            let result = channel.send_to(&alloc::vec![0; i], None);
            assert!(result.is_ok());
        }

        // Next send should fail
        let result = channel.send_to(&[99], None);
        assert!(matches!(result, Err(SendError::BufferFull)));
    }

    #[test]
    fn datagram_channel_rx_full() {
        let queue_size = 4;
        let channel: DatagramSocketChannel<TestPlatform> =
            new_datagram_channel_with_capacity(queue_size);

        let dummy_addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::LOCALHOST,
            1234,
        ));

        // Fill the RX queue
        for i in 0..queue_size {
            let data: Box<[u8]> = alloc::vec![0; i].into_boxed_slice();
            let result = channel.try_recv_datagram_with(|| Some((data, dummy_addr)));
            assert!(result.is_some());
        }

        // Queue should be full
        assert!(channel.is_rx_full());

        // Next push should fail (returns None when full)
        let result = channel.try_recv_datagram_with(|| Some((Box::from([99u8]), dummy_addr)));
        assert!(result.is_none());
    }

    #[test]
    fn datagram_channel_truncation() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        let dummy_addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::LOCALHOST,
            1234,
        ));

        // Push a large datagram
        let data: Box<[u8]> = alloc::vec![42u8; 100].into_boxed_slice();
        channel
            .try_recv_datagram_with(|| Some((data.clone(), dummy_addr)))
            .unwrap();

        // Read with a small buffer (no TRUNC flag)
        let mut buf = [0u8; 10];
        let read = channel
            .try_read(&mut buf, super::super::ReceiveFlags::empty(), None)
            .unwrap();
        assert_eq!(read, 10); // Only returns what fits in buffer
    }

    #[test]
    fn datagram_channel_trunc_flag() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        let dummy_addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::LOCALHOST,
            1234,
        ));

        // Push a large datagram
        let data: Box<[u8]> = alloc::vec![42u8; 100].into_boxed_slice();
        channel
            .try_recv_datagram_with(|| Some((data.clone(), dummy_addr)))
            .unwrap();

        // Read with TRUNC flag - should return actual packet size
        let mut buf = [0u8; 10];
        let read = channel
            .try_read(&mut buf, super::super::ReceiveFlags::TRUNC, None)
            .unwrap();
        assert_eq!(read, 100); // Returns actual datagram size
    }

    #[test]
    fn datagram_channel_io_events() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        let dummy_addr = core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::LOCALHOST,
            1234,
        ));

        // Initially: no IN, has OUT
        let events = channel.check_io_events();
        assert!(!events.contains(Events::IN));
        assert!(events.contains(Events::OUT));

        // Push a datagram using try_recv_datagram_with
        channel
            .try_recv_datagram_with(|| Some((Box::from(*b"test"), dummy_addr)))
            .unwrap();

        // Now has IN
        let events = channel.check_io_events();
        assert!(events.contains(Events::IN));
        assert!(events.contains(Events::OUT));
    }

    #[test]
    fn datagram_channel_try_send_failure() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        // Send a datagram (user side)
        let addr = Some(core::net::SocketAddr::V4(core::net::SocketAddrV4::new(
            core::net::Ipv4Addr::new(10, 0, 0, 1),
            8080,
        )));
        channel.send_to(b"Hello!", addr).unwrap();

        // Try to send but fail (return false)
        let result = channel.try_send_datagram_with(|_data, _dest| {
            false // simulate send failure
        });
        assert_eq!(result, Some(false));

        // Datagram should still be in queue
        assert!(channel.has_pending_tx());

        // Try again and succeed
        let result = channel.try_send_datagram_with(|data, dest| {
            assert_eq!(data, b"Hello!");
            assert_eq!(dest, addr);
            true
        });
        assert_eq!(result, Some(true));

        // No more pending TX
        assert!(!channel.has_pending_tx());
    }

    #[test]
    fn datagram_channel_try_recv_none() {
        let channel: DatagramSocketChannel<TestPlatform> = new_datagram_channel();

        // Closure returns None - nothing should be pushed
        let result = channel.try_recv_datagram_with(|| None);
        assert!(result.is_none());

        // Should still not be readable
        assert!(!channel.is_readable());
    }
}
